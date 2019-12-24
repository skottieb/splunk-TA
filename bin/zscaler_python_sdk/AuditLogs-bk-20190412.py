
import json
import csv
import logging
import time
from pprint import pprint
import inspect

class AuditLogs(object):

	def get_audit_report(self, start, end, output = "raw"):
		#Can be called for upto 3 return types.  RAW output (full response. object), CSV (with headers row) or JSON

		uri = self.api_url + 'api/v1/auditlogEntryReport/download'

		if self.debug:
			logging.debug("DEBUG: ##########  GENERATING REPORT  ##########\n\n")
		generate = self.generate_audit_report(start, end)
	#	print("\n\n ##########  GENERATING API RESPONSE  ##########")
		#print(generate)
		#if generate is "Status Code: 204":
			#print("\n\n ##########  GENERATING AUDIT REPORT SUCCESS  ##########\n\n" + generate)
		#else:
			#print("\n\n ##########  FAILED TO GENERATE REPORT  ##########\n\n" + generate)
			#return

		if self.debug:
			logging.debug("##########  CHECKING STATUS  ##########\n\n")
		status=self.check_audit_status() 
		#print(status + "\n")
		
		#don't try to download report while status is executing
		#there's more response types for this call we could look to handle too.  
		while status == "EXECUTING":
			status=self.check_audit_status() 
			if self.debug:
				logging.debug("Looping ServerSideStatus=" + status + "\n")
			
			time.sleep(1)

		#print("\n\n STATUS: " + status + "\n\n")
		if self.debug:
			logging.debug("##########  AUDIT REPORT GENERATED  ##########\n\n")

		res = self._perform_get_request(
			uri,
			self._set_header(self.jsessionid)
		)
		if self.debug:
			logging.debug("API RESPONSE -\n"+res.text)

		if output == "raw":
			#return full response object, easy
			return res

		if output == "json":

			# Parse the CSV into JSON   
			# read response into an array, then dump array inro json.dumps() and return JSON blob
			# Zscale CSV response is not the cleanest, startes with some kv pairs in first 4 rows, then CSV header, then data
			# data is also split across multiple lines.  While CSV compliant, it took some work to massage this into proper JSON
			# response nests all pre/post change-actions into a single text glob, later we could iterate the blobs into the array nest, further imrpoving JSON generation
			# skottieb:)

			#initialise a bunch of vars ioutsoef of the lower loops
			index = 0
			incIndex = True
			output = {}
			blob = ""
			name = ""
			multiline = False
			linealone = False
			postAction = False
			preAction = False
			blob = ""
			lineNo = 0
			startpostaction = ""
			keyindex = 0
			logentry="log"
			JSONoutput={}
			JSONoutput[logentry] = []
			kvpair = {}
			self.debug = True


			# Iterate over each line of the response, adding to array/list as we go.  
			# Pre and Post actions need special handling as these fields are split over multiple lines
			# Pre and post actiona may be futher iterated for more complete JSON / nesting.  May do this in future
			# skottieb:)
			for line in res.text.splitlines():
				if self.debug:
					logging.debug("----> CSV Line (" + str(lineNo) + "): " + line)
				
				if index < 4:
					#create top of JSON with file creation-data, use first 4 lines from Zscaler CSV response (create time, start time, end time, user)

					#split nto NV pair
					data = line.split(",")
					JSONoutput[data[0]] = data[1].strip('"')
				
				if index is 4:
					#setup array keynames based on header row of csv
					#some cells are multiline, this is handled below (where index>4)
					keynames = [ '{}'.format(x) for x in list(csv.reader([line], delimiter=',', quotechar='"'))[0] ]
					
					if self.debug:
						for i in keynames:
							logging.debug(i)

				if index > 4:
					#create log entry
					keyvalues = [ '{}'.format(x) for x in list(csv.reader([line], delimiter=',', quotechar='"'))[0] ]
					keyValLength = len(keyvalues)
					
					#if multiline == False:
						#JSONoutput[logentry].append(index)
						#JSONoutput[logentry][index] = {}

					
					# keyindex numners 10 and 11 represent pre and post actions respectivley
					# see after this loop for generation of pre and post action fields
					if keyindex < 10:
						for name in keynames:

							#stop pre and post action blobs from being overwritten
							#pre and post actions are handled after this for loop
							if keyindex > 9:
								multiline = True
								break
						
							value = keyvalues[keyindex]
							#print(name + ":" + value)
						
							#print("no multilline detectred")
							kvpair[name] = value
							#JSONoutput[logentry].append(kvpair)
							if self.debug:
								logging.debug( "in no multiline...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + value +"']")
								#pprint(JSONoutput)

							keyindex += 1


					# Initial array data generated above.  
					# Here we need to iterate over CSV lines which have pre and post action data

					#build pre-action data blob (key index is 10)
					if keyindex == 10:
						name = keynames[keyindex]

						if keyValLength > 10:
							# we know this is the first line of a pre-action as it will be contained as data-element 10 in the Zscaler CSV line
							# lines after this will litle or zero commas, meaing we won;t get to data-element 10

							#initialise blob and copy in first part of 'action'
							blob = ""
							blob += keyvalues[keyindex]
							if (blob == ""):
								if self.debug:
									logging.debug( "no-pre-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")

								kvpair[name] = blob	
								#JSONoutput[logentry].append(kvpair)
								keyindex += 1
							else:
								if self.debug:
									logging.debug( "pre-action-start...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
									#pprint(output[index])
								lineNo += 1
								incIndex = False

						elif line.startswith('","'):
							#if we're here we've hit the end of the pre action and start of a post-action entry
							startpostaction = keyvalues[0]
							startpostaction = startpostaction.strip('"')
							startpostaction = startpostaction.strip('"')
							if self.debug:
								logging.debug( "in startpostaction...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							lineNo += 1
							incIndex = False
							keyindex += 1
							kvpair[name] = blob	
							JSONoutput[logentry].append(kvpair)
							blob = ""
							if self.debug:
								pass
								#pprint(output[index])
							continue

						elif line.startswith('",,'):
							#if we hit here we've hut the final entry for this action
							#next interation will be new CSV line.  Array index incremenrted

							startpostaction = keyvalues[0]
							startpostaction = startpostaction.strip('"')
							startpostaction = startpostaction.strip('"')
							if self.debug:
								logging.debug( "Detected End...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							multiline = False
							kvpair[name] = blob	
							JSONoutput[logentry].append(kvpair)
							if self.debug:
								pass
								#pprint(output[index])
							blob = ""
							lineNo += 1
							index += 1
							keyindex = 0
							continue

						#build post-action data blob
						else:
							blob += line
							if self.debug:
								logging.debug( "in pre-action-build...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							lineNo += 1
							continue
						
					if keyindex == 11:
						#essentailly a repeat of the above 'if keyindex == 11:' logic.  See there for more detailed comments
						name = keynames[keyindex]

						if keyValLength > 10:
							blob = ""
							blob += keyvalues[keyindex]
							if (blob == ""):
								if self.debug:
									logging.debug( "no post-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
								#print( "no post-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")

								kvpair[name] = blob	
								JSONoutput[logentry].append(kvpair)
								if self.debug:
									pass
									#pprint(output[index])
								multiline = False
								incIndex = True
								keyindex = 0
							else:
								if self.debug:
									logging.debug( "start post-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
								#print( "start post-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
								incIndex = False
								lineNo += 1
								continue

						elif line.startswith('",'):
							if self.debug:
								logging.debug("Detected end")
							#print("Detected end" + blob)
							multiline = False
							kvpair[name] = blob	
							#print("\n\n\t\tKV PAIR=")
							#pprint(kvpair)
							#print("\n\n")
							JSONoutput[logentry].append(kvpair)
							#pprint(JSONoutput)
							#print("\n\n")
							if self.debug:
								pass
								#pprint(output[index])
							lineNo += 1
							keyindex = 0
							index += 1
							kvpair = {}
							continue
							
						else:
							blob += line
							if self.debug:
								logging.debug( "in post-action-build...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							#print( "in post-action-build...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							lineNo += 1
							continue

				#only increment index if not handling a multiline
				#a lot of continue statements mean we will rarely gets here when processing multiline.
				if incIndex is True:
					index += 1

				lineNo += 1

				# Nest dict intto logentry key, this will happen for each log entry after the CSV header (line 5)
				#if index > 5:
				#	JSONoutput[logentry].append(kvpair)
				#	kvpair = {}
				

			if self.debug:
				pass
				#logging.debug("\n\n")
				
			#pprint(JSONoutput)

			#print("START\n\n")
			#pprint(JSONoutput)
			jsonData=json.dumps(JSONoutput)	
			#print("END\n\n")		
			return (jsonData)

		if output == "csv":
			index = 0
			csvdata = ""

			for line in res.text.splitlines():
				if index > 3:
					csvdata += line + "\n"
					
				index += 1

			return csvdata
				

	def parse_blob(self, blob):
		actions = {}
		return actions

	def generate_audit_report(self, start, end, retry=True):

		uri = self.api_url + 'api/v1/auditlogEntryReport'

		body = {
			"startTime": start,
			"endTime": end,
 			"page": 1,
			"pageSize": 100
		}

		res = self._perform_post_request(
			uri,
			body,
			self._set_header(self.jsessionid)
		)

		#HANDLE JSON Response
		# Sample Response when rate-liomited (see next line)
		# {'message': 'Rate Limit (2/SECOND) exceeded', 'Retry-After': '0 seconds'}
		# Rate limiting returne HTPT Status Code: 429

		#data = res.json()

		#if res.response is 429:
		#	logging.debug("Over Rate Limit")
		#	if retry:
		#		while res.response is 429:
		#			time.sleep(5)
		#			logging.debug("Over Rate Limit - trying again")
		#			res = self._perform_post_request(
		#			uri,
		#			body,
		#			self._set_header(self.jsessionid)
		#		)
		#	else:
		#		return False

		return res



	def check_audit_status(self):

		uri = self.api_url + 'api/v1/auditlogEntryReport'

		res = self._perform_get_request(
			uri,
			self._set_header(self.jsessionid)
		)

		if self.debug:
			logging.debug("\n\n ##########  Getting API RESPONSE  ##########\n\n")
		
		# HANDLE JSON Response
		# Sample Response when rate-liomited (see next line)
		# {'message': 'Rate Limit (2/SECOND) exceeded', 'Retry-After': '0 seconds'}
		# Rate limiting returne HTTP Status Code: 429

		#if res.status_code == 404:
		#	return False
		#print(res.status_code)

		#pprint(res)
		data = res.json()
		logging.debug(data)


		return data['status']