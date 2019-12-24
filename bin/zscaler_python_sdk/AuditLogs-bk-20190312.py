
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
			logging.debug("DEBUG: ##########  CHECKING STATUS  ##########\n\n")
		status=self.check_audit_status() 
		#print(status + "\n")
		
		#don't try to download report while status is executing
		#there's more response types for this call we could look to handle too.  
		while status == "EXECUTING":
			status=self.check_audit_status() 
			if self.debug:
				logging.debug("DEBUG: Looping ServerSideStatus=" + status + "\n")
			
			time.sleep(1)

		#print("\n\n STATUS: " + status + "\n\n")
		if self.debug:
			logging.debug("DEBUG: ##########  AUDIT REPORT GENERATED  ##########\n\n")

		res = self._perform_get_request(
			uri,
			self._set_header(self.jsessionid)
		)
		if self.debug:
			logging.debug("DEBUG: - API RESPONSE -\n"+res.text)

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


			# Iterate over each line of the response, adding to array/list as we go.  
			# Pre and Post actions need special handling as these fields are split over multiple lines
			# Pre and post actiona may be futher iterated for more complete JSON / nesting.  May do this in future
			# skottieb:)
			for line in res.text.splitlines():
				if self.debug:
					logging.debug("DEBUG: ----> CSV Line (" + str(lineNo) + "): " + line)
				
				if index < 4:
					#create top of JSON with file creation-data, use first 4 lines from Zscaler CSV response (create time, start time, end time, user)

					#split nto NV pair
					data = line.split(",")
					output[data[0]] = data[1].strip('"')
				
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
					
					if multiline == False:
						output[index] = {}

					
					# keyindex numners 10 and 11 represent pre and post actions respectivley
					# see after this loop for generate of pre and post action fields
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
							output[index][name] = value
							if self.debug:
								logging.debug( "DEBUG: in no multiline...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + value +"']")

							keyindex += 1


					# Initial array data generated above.  
					# Here we need to itnerate of CSV lines which have pre and post action data

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
									logging.debug( "DEBUG: no-pre-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
								output[index][name] = blob
								keyindex += 1
							else:
								if self.debug:
									logging.debug( "DEBUG: pre-action-start...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
									#pprint(output[index])
								lineNo += 1
								incIndex = False

						elif line.startswith('","'):
							#if we're here we've hit the end of the pre action and start of a post-action entry
							startpostaction = keyvalues[0]
							startpostaction = startpostaction.strip('"')
							startpostaction = startpostaction.strip('"')
							if self.debug:
								logging.debug( "DEBUG: in startpostaction...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							lineNo += 1
							incIndex = False
							keyindex += 1
							output[index][name] = blob
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
								logging.debug( "DEBUG: Detected End...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							multiline = False
							output[index][name] = blob
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
								logging.debug( "DEBUG: in pre-action-build...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
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
									logging.debug( "DEBUG: no post-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
								output[index][name] = blob
								if self.debug:
									pass
									#pprint(output[index])
								multiline = False
								incIndex = True
								keyindex = 0
							else:
								if self.debug:
									logging.debug( "DEBUG: start post-action...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
								incIndex = False
								lineNo += 1
								continue

						elif line.startswith('",'):
							if self.debug:
								logging.debug("DEBUG: Detected end")
							multiline = False
							output[index][name] = blob
							if self.debug:
								pass
								#pprint(output[index])
							lineNo += 1
							keyindex = 0
							index += 1
							continue
							
						else:
							blob += line
							if self.debug:
								logging.debug( "DEBUG: in post-action-build...\tindex:['" + str(index) + "'}count:(" + str(keyindex) + ")\tname['" + name + "']  :  value['" + blob +"']")
							lineNo += 1
							continue

				#only increment index if not handling a multiline
				#a lot of continue statements mean we will rarely gete here when processing multiline.
				if incIndex is True:
					index += 1

				lineNo += 1
				

			if self.debug:
				pass
				#logging.debug("\n\n")
				#pprint(output)

			# print("START\n\n")
			jsonData=json.dumps(output)	
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
				


	def generate_audit_report(self, start, end):

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
		return res



	def check_audit_status(self):

		uri = self.api_url + 'api/v1/auditlogEntryReport'

		res = self._perform_get_request(
			uri,
			self._set_header(self.jsessionid)
		)

		if self.debug:
			logging.debug("\n\n ##########  Getting API RESPONSE  ##########\n\n")
		#HANDLE JSON Response
		data = res.json()
		#logging.debug(data['status']+ "\n\n")		

		return data['status']