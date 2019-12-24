import splunklib.results as results
from splunklib.modularinput import *
import splunklib.client as client
import os
import sys
import time
import zscaler_python_sdk


class MyScript(Script):
	
	# Define some global variables
	MASK           = "************"
	APP            = __file__.split(os.sep)[-3]
	USERNAME       = None
	CLEAR_PASSWORD = None
	CLEAR_KEY = None

	def get_scheme(self):

		scheme = Scheme("Zscaler Sandbox")
		scheme.description = ("Get Zscaler Sandbox detonation results logs into Splunk")
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
				ew.log("DEBUG", "Storeage Password: USERNAME:%s PASSWORD:**** REALM:%s" % (storage_password.username, storage_password.realm))

				if (storage_password.username == username and storage_password.realm == realm):
					ew.log("DEBUG", "Deleting: USERNAME:%s PASSWORD:**** REALM:%s" % (storage_password.username, storage_password.realm))
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
		#service = client.connect(**args)
		#print args
		
		
		try:
			#service = client.connect(host="127.0.0.1", port=8089, username="zscaler", password="Zscal3r!")
			service = client.connect(**args)
			kwargs_oneshot = {"earliest_time": "-1h", "latest_time": "now",}
			searchquery_oneshot = "| inputlookup zscaler-md5-lookup.csv | dedup md5"
			oneshotsearch_results = service.jobs.oneshot(searchquery_oneshot, **kwargs_oneshot)
			return oneshotsearch_results

		except Exception as e:
			raise Exception, "Boo!: %s" % str(e)

	def stream_events(self, inputs, ew):
		self.input_name, self.input_items = inputs.inputs.popitem()
		session_key = self._input_definition.metadata["session_key"]
		username = self.input_items["apiuser"]
		password   = self.input_items['apipass']
		apikey   = self.input_items['apikey']


		# Run a one-shot search and display the results using the results reader
		md5List = self.get_md5_list(username, password, session_key)

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

		# Get the results and display them using the ResultsReader
		reader = results.ResultsReader(md5List)
		for item in reader:
                        if(item["md5"] == "none"):
                            ew.log("INFO", "STOP: No queued MD5")
                            break
			ew.log("INFO", "Checking Zscaler Sandbox for MD5 : %s" % item["md5"])
			quota = z.check_sandbox_quota()
			#print(quota)
			ew.log("INFO", "Sandbox current quota : %s" % quota)

			while quota['unused'] <= 0:
				quota = z.check_sandbox_quota()
				ew.log("INFO","waiting 1 sec...\tquota_left[" + str(quota['unused']) + "']")
				
				time.sleep(1)

			ew.log("INFO", "Loading Zscaler Sandbox for MD5 : %s" % item["md5"])
			report = z.get_sandbox_report(item["md5"], "full")
			#ew.log("INFO", "Sandbox REPORT : %s" % report.text)
			#print(item["md5"])
			event = Event()
			#event.stanza = input_name
			event.data = report.text
			ew.write_event(event)
					
		

if __name__ == "__main__":
	exitcode = MyScript().run(sys.argv)
	sys.exit(exitcode)

