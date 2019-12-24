import splunklib.results as results
from splunklib.modularinput import *
import splunklib.client as client
import os
import sys
import time
import json
import xml
import zscaler_python_sdk


class MyScript(Script):
	
	# Define some global variables
	MASK           = "************"
	APP            = __file__.split(os.sep)[-3]
	USERNAME       = None
	CLEAR_PASSWORD = None
	CLEAR_KEY = None

	def get_checkpoint_dir(self):

		try:
			# read everything from stdin
			config_str = sys.stdin.read()

			doc = xml.dom.minidom.parseString(config_str)
			root = doc.documentElement

			checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]

			if checkpnt_node and checkpnt_node.firstChild and checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
				return checkpnt_node.firstChild.data
		
		except Exception, e:
			raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)


	def get_scheme(self):

		scheme = Scheme("Zscaler Audit Logs")
		scheme.description = ("Get Zscaler Admin Audit Logs results logs into Splunk")
		scheme.use_external_validation = False
		scheme.streaming_mode_xml = False
		scheme.use_single_instance = False

		username_arg = Argument(
			name="apiuser",
			title="User name",
			data_type=Argument.data_type_string,
			required_on_create=True,
			required_on_edit=True
		)
		scheme.add_argument(username_arg)
		
		password_arg = Argument(
			name="apipass",
			title="Password",
			data_type=Argument.data_type_string,
			required_on_create=True,
			required_on_edit=True
		)
		scheme.add_argument(password_arg)

		password_arg = Argument(
			name="apikey",
			title="API Key",
			data_type=Argument.data_type_string,
			required_on_create=True,
			required_on_edit=True
		)

		password_arg = Argument(
			name="name",
			title="Input Name",
			data_type=Argument.data_type_string,
			required_on_create=True,
			required_on_edit=True
		)

		scheme.add_argument(password_arg)

		return scheme

	def validate_input(self, definition):
		session_key = definition.metadata["session_key"]
		username    = definition.parameters["apiuser"]
		password    = definition.parameters["apipass"]
		apikey    = definition.parameters["apikey"]
		
		try:
			# Do checks here.  For example, try to connect to whatever you need the credentials for using the credentials provided.
			# If everything passes, create a credential with the provided input.
			pass
		except Exception as e:
			raise Exception, "Something did not go right: %s" % str(e)

	def encrypt_password(self, username, password, realm, session_key, ew):
		args = {'token':session_key}
		service = client.connect(**args)
		
		try:
			# If the credential already exists, delte it.
			for storage_password in service.storage_passwords:
				#ew.log("DEBUG", "Storeage Password: USERNAME:%s PASSWORD:%s REALM:%s" % (storage_password.username, storage_password.password, storage_password.realm))

				if (storage_password.username == username and storage_password.realm == realm):
					#ew.log("DEBUG", "Deleting: USERNAME:%s PASSWORD:%s REALM:%s" % (storage_password.username, storage_password.password, storage_password.realm))
					service.storage_passwords.delete(username=username, realm=realm)
					break

			# Create the credential.
			ew.log("INFO", "Creating Credential USERNAME:%s PASSWORD:**** REALM:%s" % (username, realm))
			service.storage_passwords.create(password, username, realm)

		except Exception as e:
			raise Exception, "An error occurred updating credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities. Details: %s" % str(e)


	def mask_password(self, session_key, username, password, type):
		try:
			args = {'token':session_key}
			service = client.connect(**args)
			kind, input_name = self.input_name.split("://")
			item = service.inputs.__getitem__((input_name, kind))
			
			if type == "password":
				kwargs = {
					"apiuser": username,
					"apipass": self.MASK,
					"apikey": password
				}
				item.update(**kwargs).refresh()
			
			if type == "apikey":
				kwargs = {
					"apiuser": username,
					"apipass": password,
					"apikey": self.MASK
				}
				item.update(**kwargs).refresh()
			
		except Exception as e:
			raise Exception("Error updating inputs.conf: %s" % str(e))


	def get_password(self, session_key, username, realm):
		args = {'token':session_key}
		service = client.connect(**args)

		# Retrieve the password from the storage/passwords endpoint	
		for storage_password in service.storage_passwords:
			if (storage_password.username == username and storage_password.realm == realm):
				return storage_password.content.clear_password

	def get_md5_list(self, username, password, session_key):
		args = {'token':session_key}
		
		
		try:
			service = client.connect(**args)
			kwargs_oneshot = {"earliest_time": "-1h", "latest_time": "now",}
			searchquery_oneshot = "| inputlookup zscaler-md5-lookup.csv | dedup md5"
			oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
			return oneshotsearch_results

		except Exception as e:
			raise Exception, "Boo!: %s" % str(e)

	def save_checkpoint(self, time, file):
		f = open(file, "w")
		f.write(str(time))
		f.close()

	def load_checkpoint(self, file):
		try:
			f = open(file, "r")
			lastTime = f.read()
			f.close()
			return lastTime

		except:
			# assume that this means the checkpoint is not there
			return False


	def stream_events(self, inputs, ew):
		self.input_name, self.input_items = inputs.inputs.popitem()
		session_key = self._input_definition.metadata["session_key"]
		username = self.input_items["apiuser"]
		password   = self.input_items['apipass']
		apikey   = self.input_items['apikey']
		filename = self.input_name.split("://")

		checkpoint_dir = self._input_definition.metadata["checkpoint_dir"]		
		file = os.path.join(checkpoint_dir, filename[1])
		

		# Setup Credentails for Zscaler API Login, these are stored encrypted using Splunk's API's
		self.USERNAME = username
		kind, input_name = self.input_name.split("://")
		api_realm = kind + input_name + "__API__" 
		pass_realm = kind + input_name + "__PASS__"

		try:
			# If the password is not masked, mask it.
			if password != self.MASK:
				ew.log("INFO", "Encrypting Password")
				self.encrypt_password(username, password, pass_realm, session_key, ew)
				ew.log("INFO", "Masking Password")
				self.mask_password(session_key, username, apikey, "password")

			ew.log("INFO", "Getting Clear Passsword")
			self.CLEAR_PASSWORD = self.get_password(session_key, username, pass_realm)

			# If the apikey is not masked, mask it.
			if apikey != self.MASK:
				ew.log("INFO", "Encrypting APIKEY")
				self.encrypt_password(username, apikey, api_realm, session_key, ew)
				ew.log("INFO", "Masking APIKEY")
				self.mask_password(session_key, username, password, "apikey")

			ew.log("INFO", "Getting Clear APIKEY")
			self.CLEAR_KEY = self.get_password(session_key, username, api_realm)

		except Exception as e:
			ew.log("ERROR", "Error: %s" % str(e))
			print("ERROR", "Error: %s" % str(e))

		#Set envvars based on clear creds
		os.environ["ZIA_USERNAME"] = self.USERNAME
		os.environ["ZIA_PASSWORD"] = self.CLEAR_PASSWORD
		os.environ["ZIA_API"] = self.CLEAR_KEY

		#API Login
		ew.log("INFO", "Login to Zscaler API: %s" % username)

		z = zscaler_python_sdk.zscaler()
		z.get_zia_creds_from_env(True)
		z.set_cloud(self.input_items['cloud'])
		z.authenticate_zia_api()

		ew.log("INFO", "Login Success")

		# Get Audit Report

		#load starttime from checkpoint file
		ew.log("DEBUG", "Loading Checkpoint: " + file)
		stime = self.load_checkpoint(file)
		#if we get no time for checpoint default to 10 mins ago
		if(not stime):
			#set strt time a week ago, end time now
			ew.log("DEBUG", "Cant determine last execiting time, using default [last 10 mins]")
			startOffset = 604800
			stime = int(round(time.time() * 1000)-startOffset)-1000

		etime = int(round(time.time() * 1000)) -1000

		ew.log("INFO", "Generating Report: " + str(stime) + "-" + str(etime))
		generate = z.generate_audit_report(stime, etime)
		ew.log("INFO", "Report generated status(" + str(generate.status_code) + ") :" + str(generate.text))
			#	print("\n\n ##########  GENERATING API RESPONSE  ##########")
		#print(generate)
		#if generate is "Status Code: 204":
			#print("\n\n ##########  GENERATING AUDIT REPORT SUCCESS  ##########\n\n" + generate)
		#else:
			#print("\n\n ##########  FAILED TO GENERATE REPORT  ##########\n\n" + generate)
			#return
		
		#if generate is not "Status Code: 204":
		#	ew.log("INFO", "API Error: " + str(generate.text))
		#	return
		
		status = z.check_audit_status() 
		#print(status + "\n")
		
		#don't try to download report while status is executing
		#there's more response types for this call we could look to handle too.  
		while status == "EXECUTING":
			status=z.check_audit_status() 
			ew.log("INFO", "Looping Audit Log still generating, ServerSideStatus=" + status)
			
			time.sleep(1)

		ew.log("INFO","##########  AUDIT REPORT GENERATED  ##########\n\n")

		report = z.get_audit_report("json")
		logs = json.loads(report)

		for (key, value) in logs.items():
			#ew.log("DEBUG", "Key: " + str(key))

			if(key == "log"):
				for log in value:
					#ew.log("DEBUG", "Log: " + str(log))
					event = Event()
					event.data = json.dumps(log)
					ew.write_event(event)
		
		ew.log("DEBUG", "Saving Chekpoint: " + file)
		self.save_checkpoint(etime, file)

if __name__ == "__main__":
	exitcode = MyScript().run(sys.argv)
	sys.exit(exitcode)
