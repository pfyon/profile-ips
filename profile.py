#!/usr/bin/env python3

import argparse
import logging
import numpy
import pandas
import sys

class Profiler(object):
	def __init__(self, path):
		self._path = path
		self._column_types = {'ip': 'Int64', 'ts_start': 'Float64', 'ts_end': 'Float64', 'src_port': 'Int32', 'dst_port': 'Int32', 'pkts_toclient': 'Int32', 'pkts_toserver': 'Int64', 'bytes_toclient': 'Int64', 'bytes_toserver': 'Int32', 'proto': 'Int32', 'app': str}

	def profileIps(self):
		#Read the file into a dataframe
		log.debug("Reading csv")
		flow_df = pandas.read_csv(self._path, dtype=self._column_types)

		#Generate statistics for each IP over each hour
		log.debug("Extracting hour from ts_start")
		#flow_df['ts_start'] = pandas.to_datetime(flow_df['ts_start'], unit='s')
		flow_df['hour'] = pandas.DatetimeIndex(pandas.to_datetime(flow_df['ts_start'], unit='s')).hour

		log.debug("Grouping by ip and hour")
		#flow_df['hour'] = pandas.DatetimeIndex(flow_df.ts_start)
		#flow_df['hour'] = pandas.DatetimeIndex(flow_df.ts_start).hour
		#times = pandas.DatetimeIndex(flow_df.ts_start)
		grouped = flow_df[flow_df['ip'].between(3232238848, 3232239103)].groupby([flow_df.ip, flow_df.hour])
		print(grouped.bytes_toclient.mean())
		print(grouped.bytes_toclient.max())
		print(grouped.bytes_toclient.count())

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Create time-based statistics about flow records of IP addresses.")
	parser.add_argument("path", help="Path to csv file of flow records", type=str)
	parser.add_argument("--debug", action='store_true', dest='debug', default=False)
	args = parser.parse_args()

	logging.basicConfig(stream=sys.stdout, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

	log = logging.getLogger(sys.argv[0])
	if args.debug:
		log.setLevel(logging.DEBUG)
	else:
		log.setLevel(logging.INFO)

	profiler = Profiler(args.path)
	profiler.profileIps()
