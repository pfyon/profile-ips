#!/usr/bin/env python3

import argparse
import collections
import csv
import datetime
import gzip
import json
import logging
import netaddr
import os
import sys

class Processor(object):
	def __init__(self, path, dest, important_ips):
		self._path = path
		self._dest = dest
		self._ips = important_ips
		self._columns = ['ip', 'ts_start', 'ts_end', 'src_port', 'dst_port', 'pkts_toclient', 'pkts_toserver', 'bytes_toclient', 'bytes_toserver', 'proto', 'app']
		self.Record = collections.namedtuple('Record', self._columns)

		if os.path.exists(self._dest):
			if not os.path.isfile(self._dest):
				raise IsADirectoryError(f"'{self._dest}' is a directory")
			else:
				raise FileExistsError(f"'{self._dest}' already exists")

	def process(self):
		if os.path.exists(self._path):
			with open(self._dest, 'w', newline='') as csvfile:
				writer = csv.writer(csvfile)
				writer.writerow(self._columns)

				if not os.path.isfile(self._path):
					#a directory
					for filename in os.listdir(self._path):
						self._processFile(os.path.join(self._path, filename), writer)
				else:
					#a file
					self._processFile(self._path, writer)
		else:
			raise FileNotFoundError(f"'{self._path}' doesn't exist")

	def _processFile(self, path, csvwriter):
		count = 0
		try:
			f = gzip.GzipFile(path, mode='r')
			f.peek(10) #Test to see if it's a real gzip file
			log.debug(f"'{path}' is a gzip file")
		except OSError as e:
			#Not gzipped
			f = open(path, 'r')
			log.debug(f"'{path}' is a regular file")

		try:
			for line in f:
				try:
					msg = json.loads(line)
					if msg.get('event_type', None) == 'flow':
						ip = None
						if 'src_ip' in msg and netaddr.IPAddress(msg.get('src_ip')) in self._ips:
							ip = netaddr.IPAddress(msg.get('src_ip'))
						elif 'dest_ip' in msg and netaddr.IPAddress(msg.get('dest_ip')) in self._ips:
							ip = netaddr.IPAddress(msg.get('dest_ip'))
	
						if ip is not None:
							ts_start = None
							ts_end = None
							src_port = None
							dst_port = None
							pkts_toclient = None
							pkts_toserver = None
							bytes_toclient = None
							bytes_toserver = None
							proto = None
							app = None
		
							src_port = int(msg['src_port'])  if 'src_port'  in msg else None
							dst_port = int(msg['dest_port']) if 'dest_port' in msg else None
		
							proto = msg.get('proto', None)
		
							if proto == 'TCP':
								proto = 6
							elif proto == 'UDP':
								proto = 17
							elif proto == 'ICMP':
								proto = 1
							elif proto == 'IPv6-ICMP': 
								proto = 58
							elif proto == 'SCTP':
								proto = 132
							elif proto is None:
								pass
							else:
								log.warn(f"Unsupported protocol '{proto}'")
								log.warn(msg)
		
							app = msg.get('app_proto', None)
							
							if 'flow' in msg:
								if 'start' not in msg['flow'] or 'end' not in msg['flow']:
									log.debug("Skipping this record - it's missing a start or end in flow")
									continue
		
								ts_start = datetime.datetime.strptime(msg['flow']['start'], '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
								ts_end   = datetime.datetime.strptime(msg['flow']['end'],   '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
		
								pkts_toclient = msg['flow'].get('pkts_toclient', None)	
								pkts_toserver = msg['flow'].get('pkts_toserver', None)	
		
								bytes_toclient = msg['flow'].get('bytes_toclient', None)
								bytes_toserver = msg['flow'].get('bytes_toserver', None)
								
							record = self.Record(
								ip.value,
								ts_start,
								ts_end,
								src_port,
								dst_port,
								pkts_toclient,
								pkts_toserver,
								bytes_toclient,
								bytes_toserver,
								proto,
								app
							)
							count += 1
							csvwriter.writerow(record)
				except json.decoder.JSONDecodeError:
					log.debug(line)
					pass
		finally:
			f.close()

		log.debug(f"Found {count} flow records")
		return count

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Parse one or more eve.json files and extract flow into a csv file suitable for profile.py")
	parser.add_argument("path", help="Path to eve file or directory containing eve files", type=str)
	parser.add_argument("--dest", help="Path to csv file to write the results to", default="flow.csv", type=str)
	parser.add_argument("--ip", help="Extract information about this list of IPs or CIDR ip ranges", required=True, type=str)
	parser.add_argument("--debug", action='store_true', dest='debug', default=False)
	args = parser.parse_args()

	logging.basicConfig(stream=sys.stdout, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

	log = logging.getLogger(sys.argv[0])
	if args.debug:
		log.setLevel(logging.DEBUG)
	else:
		log.setLevel(logging.INFO)

	important_ips = netaddr.IPSet()
	for ip in args.ip.split(','):
		important_ips.add(netaddr.IPNetwork(ip))

	log.debug(important_ips)

	processor = Processor(args.path, args.dest, important_ips)
	processor.process()
