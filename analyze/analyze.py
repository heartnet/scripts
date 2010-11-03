#!/usr/bin/python
from __future__ import with_statement  # for obsolete python
from check_type import *
from types import *
import re

# set path
cidr_list_path   ="/tmp/cidr.txt"
class_list_paths =["/tmp/class_A.txt", "/tmp/class_B.txt", "/tmp/class_C.txt"]

# Name: classify_address
# Explanation:
#   return values:
#     class A => 0
#     class B => 1
#     class C => 2
def classify_address(ip_address):
	ip_address  =check_type(StringType, ip_address)
	first_octet =int( ip_address.split(".")[0] )
	
	if 1 <= first_octet <= 126:
		return 0
	elif 128 <= first_octet <= 191:
		return 1
	elif 192 <= first_octet <= 223:
		return 2

# Name: gen_class_list
# Explanation: generate list of classified IP address from cidr.txt
def gen_class_list():
	with open(cidr_list_path, "r") as input_file:
		class_A, class_B, class_C =[], [], []
		list_of_class             =[class_A, class_B, class_C]
		re_spaces                 =re.compile("\s+")

		for line in input_file:
			line_as_array   =re_spaces.split(line.rstrip())[1].split("/")
			network_address =line_as_array[0]
			first_octet     =int( network_address.split(".")[0] )

			classified_value =classify_address(network_address)
			list_of_class[classified_value].append(line)

		for index in range(len(list_of_class)):
			with open(class_list_paths[index], "w") as output_file:
				for line in list_of_class[index]:
					output_file.write(line)

def search_address(ip_address):
	ip_address              =check_type(StringType, ip_address)
	address_class           =classify_address(ip_address)
	re_spaces               =re.compile("\s+")
	binary_target_address   =""

	for octet in ip_address.split("."):
		octet                  =int(octet)
		binary_octet           =format(octet, "b").zfill(8)
		binary_target_address +=binary_octet

	with open(class_list_paths[address_class], "r") as file:
		for line in file:
			line_as_array           =re_spaces.split(line.rstrip())[1].split("/")
			network_address         =line_as_array[0]
			subnetmask              =int(line_as_array[1])
			re_subnetmask           =re.compile("^\d{%(subnetmask)d}" % locals())
			binary_network_address  =""

			for octet in network_address.split("."):
				octet                   =int(octet)
				binary_octet            =format(octet, "b").zfill(8)
				binary_network_address +=binary_octet

			extracted_network_address =re_subnetmask.match(binary_network_address).group()
			extracted_target_address  =re_subnetmask.match(binary_target_address).group()

			if int(extracted_network_address) ^ int(extracted_target_address) == 0:
				# found
				print line,
				return 0

#gen_class_list()
search_address("202.28.27.141")
search_address("60.39.176.252")
