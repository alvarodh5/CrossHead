#!/usr/bin/python
# -*- coding: utf-8 -*-
#Autor: Alvaro Diaz Hernandez @alvarodh5
#Version 1.1
#Last Modified 20181021 @alvarodh5

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
import sys
import re
import json
import time

requests.packages.urllib3.disable_warnings()

class bcolors:
	HEADER = '\033[95m'
	BLUE = '\033[96m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	LOGO = '\033[33m'
	BCK = '\033[46m'
	ENDC = '\033[0m'

def report(title,info,table):
	report=open('Fingerprint.md','a')
	report.write('\n## '+ title + '\n')
	report.write('\n' + info + '\n')
	report.write('~~~~\n')
	report.write(table)
	report.write('\n~~~~\n\n***\n')
	report.close()

def advanced_report(url):
	print("Generating Advanced Report, wait please...")
	headers = {'API-Key': 'xxxxxxxxxxxxxxxxxxxxx'} #PUT YOUR OWN API KEY
	payload = {'url': url, 'public': 'on'}
	
	r = requests.post("https://urlscan.io/api/v1/scan/", data=payload, headers=headers)
	
	data = json.loads(r.content)
	url = data["api"]
	time.sleep(50)
	r = requests.get(url)
	data = json.loads(r.content)
	
	report_md=open('Advanced-Report.md','a')
	report_md.write('\n## '+ "Basic Info" + '\n')
	report_md.write('\n' + "Basic information:" + '\n')
	report_md.write('~~~~\n')
	
	#Basic Info
	report_md.write("Target:" + url + "\n")
	report_md.write("Country:" + str(len(data["page"]["country"])) + "("  + str(len(data["page"]["city"])) + ")" + "\n")
	report_md.write("IP:" + str(len(data["page"]["ip"])) + "\n")
	report_md.write("ASN:" + str(len(data["page"]["asn"])) + "("  + str(len(data["page"]["asnname"])) + ")")
	
	report_md.write('\n~~~~\n\n***\n')
	
	#Global Info
	report_md.write('\n## '+ "Global Info" + '\n')
	report_md.write('\n' + "Global information:" + '\n')
	report_md.write('~~~~\n')
	
	report_md.write("Requests:" + str(len(data["data"]["requests"])) + "\n")
	report_md.write("Cookies:" + str(len(data["data"]["cookies"]))+ "\n")
	report_md.write("Console:" + str(len(data["data"]["console"]))+ "\n")
	report_md.write("Links:" + str(len(data["data"]["links"]))+ "\n")
	report_md.write("Secure Requests:" + str(data["stats"]["secureRequests"])+ "\n")
	report_md.write("Secure Percentage:" + str(data["stats"]["securePercentage"])+ "\n")
	report_md.write("Total Links:" + str(data["stats"]["totalLinks"])+ "\n")
	report_md.write("Ad Blocked:" + str(data["stats"]["adBlocked"])+ "\n")
	report_md.write("Malicious Percentage:" + str(data["stats"]["malicious"]) + "%")
	
	report_md.write('\n~~~~\n\n***\n')
	
	report_md.write('\n## '+ "IPs Stats" + '\n')
	report_md.write('\n' + "IPs Stats:" + '\n')
	report_md.write('~~~~\n')
	
	for i in xrange(len(data["stats"]["ipStats"])):
		report_md.write("Domain:" + str(data["stats"]["ipStats"][i]["domains"])+ "\n")
		report_md.write("IP:" + str(data["stats"]["ipStats"][i]["ip"])+ "\n")
		report_md.write("ASN:" + str(data["stats"]["ipStats"][i]["asn"])+ "\n")
		report_md.write("DNS:" + str(data["stats"]["ipStats"][i]["dns"])+ "\n")
		report_md.write("GEOIP:" + str(data["stats"]["ipStats"][i]["geoip"]["ll"])+ "\n")
		report_md.write("Country:" + str(data["stats"]["ipStats"][i]["geoip"]["country_name"])+ "\n")
	
	report_md.write('\n~~~~\n\n***\n')
	
	report_md.write('\n## '+ "Server Fingerprint" + '\n')
	report_md.write('\n' + "Server Fingerprint:" + '\n')
	report_md.write('~~~~\n')
	
	for i in xrange(len(data["stats"]["serverStats"])):
			for j in xrange(len(data["stats"]["serverStats"][i]["ips"])):
				report_md.write(str(data["stats"]["serverStats"][i]["ips"][j]) + str(data["stats"]["serverStats"][i]["countries"])  + "(" + str(data["stats"]["serverStats"][i]["server"]) + ")")
	
	report_md.write('\n~~~~\n\n***\n')
	
	
	report_md.write('\n## '+ "IPs" + '\n')
	report_md.write('\n' + "IPs:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["ips"]))
	report_md.write('\n~~~~\n\n***\n')
	
	
	report_md.write('\n## '+ "Countries" + '\n')
	report_md.write('\n' + "Countries:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["countries"]))
	report_md.write('\n~~~~\n\n***\n')
	
	report_md.write('\n## '+ "ASNs" + '\n')
	report_md.write('\n' + "ASNs:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["asns"]))
	report_md.write('\n~~~~\n\n***\n')
	
	
	report_md.write('\n## '+ "Domains" + '\n')
	report_md.write('\n' + "Domains:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["domains"]))
	report_md.write('\n~~~~\n\n***\n')
	
	report_md.write('\n## '+ "URLs" + '\n')
	report_md.write('\n' + "URLs:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["urls"]))
	report_md.write('\n~~~~\n\n***\n')
	
	report_md.write('\n## '+ "LinkDomains" + '\n')
	report_md.write('\n' + "LinkDomains:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["linkDomains"]))
	report_md.write('\n~~~~\n\n***\n')
	
	
	report_md.write('\n## '+ "Certificates" + '\n')
	report_md.write('\n' + "Certificates:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["certificates"]))
	report_md.write('\n~~~~\n\n***\n')
	
	report_md.write('\n## '+ "Hashes" + '\n')
	report_md.write('\n' + "Hashes:" + '\n')
	report_md.write('~~~~\n')
	report_md.write(str(data["lists"]["hashes"]))
	report_md.write('\n~~~~\n\n***\n')

	
def ascii():
	print(bcolors.LOGO + "_________                              ___ ___                     .___" + bcolors.ENDC)
	print(bcolors.LOGO + "\_   ___ \_______  ____  ______ ______/   |   \   ____ _____     __| _/" + bcolors.ENDC)
	print(bcolors.LOGO + "/    \  \/\_  __ \/  _ \/  ___//  ___/    ~    \_/ __ \\__  \   / __ | " + bcolors.ENDC)
	print(bcolors.LOGO + "\     \____|  | \(  <_> )___ \ \___ \\    Y    /\  ___/ / __ \_/ /_/ | " + bcolors.ENDC)
	print(bcolors.LOGO + " \______  /|__|   \____/____  >____  >\___|_  /  \___  >____  /\____ | " + bcolors.ENDC)
	print(bcolors.LOGO + "       \/                  \/     \/       \/       \/     \/      \/ "+ bcolors.ENDC + bcolors.BLUE + "1.1" + bcolors.ENDC)
	print(bcolors.BLUE + "[*] "+bcolors.ENDC + bcolors.BLUE +"By @alvarodh5 A.K.A Blackdrake"+bcolors.ENDC + bcolors.BLUE+" [*]\n" + bcolors.ENDC)


def cms_identifier(url,r):
	print(bcolors.BLUE + "[*] " + bcolors.ENDC+ "Checking if " + bcolors.BLUE + url + bcolors.ENDC + " is a CMS...")
	pinfo = "Checking if " + url + " is a CMS..."
	body = str(r.content)
	found = 0
	if 'wp-content/' in body or 'content="WordPress' in body or 'Powered by <a href="http://wordpress.org/">WordPress </a>' in body or "xmlrpc.php" in body:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Wordpress found!")
		ptable = "[-] Wordpress found"
		found += 1
	if 'content="Joomla!' in body:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Joomla found!")
		ptable = "[-] Joomla found"
		found += 1
	if 'content="drupal' in body.lower():
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Drupal found!")
		ptable = "[-] Drupal found"
		found += 1
	if 'content="moodle-core' in body or '"moodle-filter' in body:
		print(bcolors.GREEN + "\t[i] "  + bcolors.ENDC + " Moodle found!")
		ptable = "[-] Moodle found"
		found += 1
	if found == 0:
		print(bcolors.RED + "\t[!] " + bcolors.ENDC + "CMS not found!" )
		ptable = "[-] CMS not found"
	report("CMS",pinfo,ptable)

def analyze(cabecera):
	print(bcolors.BLUE + "\n[*] " + bcolors.ENDC+"Printing Headers...\n")
	print(json.dumps(dict(r.headers),indent=4, sort_keys=True))
	print(bcolors.BLUE + "\n[*] " + bcolors.ENDC+"Analyzing headers")
	cont = 0
	ptable = ""
	pcookies = ""
	pfinger = ""

	if "x-xss-protection" not in cabecera.lower():
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"XSS Protection Header not found\n"+bcolors.RED + "\tDescription:" +bcolors.ENDC + "\n\tX-XSS-Protection sets the configuration for the cross-site scripting\n\tfilter built into most browsers.\n\tRecommended value \"X-XSS-Protection: 1; mode=block\".\n")
		ptable += "[!] XSS Protection Header not found\n"
		cont += 1
	else:
		print(bcolors.GREEN + "\t[i] "+ bcolors.ENDC+"XSS Protection Header found")
		ptable += "[i] XSS Protection Header found\n"
	if "x-frame-options" not in cabecera.lower():
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"X-Frame-Options Header not found\n"+bcolors.RED + "\tDescription:" +bcolors.ENDC + "\n\tX-Frame-Options tells the browser whether you want to allow your site to be framed or not.\n\tBy preventing a browser from framing your site you can defend against attacks like clickjacking.\n\tRecommended value \"x-frame-options: SAMEORIGIN\".\n")
		ptable += "[!] X-Frame-Options Header not found\n"
		cont += 1
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"X-Frame-Options Header found")
		ptable += "[i] X-Frame-Options Header found\n"
	if "x-permitted-cross-domain-policies" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"X-Permitted-Cross-Domain-Policies Header not found")
		ptable += "[!] X-Permitted-Cross-Domain-Policies Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"X-Permitted-Cross-Domain-Policies Header found")
		ptable += "[i] X-Permitted-Cross-Domain-Policies Header found\n"
	if "x-content-type-options" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"X-Content-Type-Options Header not found\n"+bcolors.RED + "\tDescription:" +bcolors.ENDC + "\n\tX-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it\n\tto stick with the declared content-type.\n\tThe only valid value for this header is \"X-Content-Type-Options: nosniff\".\n")
		ptable += "[!] X-Content-Type-Options Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] "+ bcolors.ENDC+"X-Content-Type-Options Header found")
		ptable += "[i] X-Content-Type-Options Header found\n"
	if "x-content-security-policy" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] "+ bcolors.ENDC+"X-Content-Security-Policy Header not found\n"+bcolors.RED + "\tDescription:" +bcolors.ENDC + "\n\tContent Security Policy is an effective measure to protect your site from XSS attacks.\n\tBy whitelisting sources of approved content, you can prevent the browser from loading malicious assets.\n")
		ptable += "[!] X-Content-Security-Policy Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+" X-Content-Security-Policy Header found")
		ptable += "[i] X-Content-Security-Policy Header found\n"
	if "access-control-allow-origin" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Allow-Origin Header not found")
		ptable += "[!] Access-Control-Allow-Origin Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Control-Allow-Origin Header found")
		ptable += "[i] Access-Control-Allow-Origin Header found\n"
	if "access-control-expose-headers" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Expose-Headers Header not found")
		ptable += "[!] Access-Control-Expose-Headers Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Control-Expose-Headers Header found")
		ptable += "[i] Access-Control-Expose-Headers Header found\n"
	if "access-control-max-age" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Max-Age Header not found")
		ptable += "[!] Access-Control-Max-Age Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Control-Max-Age Header found")
		ptable += "[i] Access-Control-Max-Age Header found\n"
	if "access-control-allow-credentials" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Allow-Credentials Header not found")
		ptable += "[!] Access-Control-Allow-Credentials Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Control-Allow-Credentials Header found")
		ptable += "[i] Access-Control-Allow-Credentials Header found\n"
	if "access-control-allow-methods" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Allow-Methods Header not found")
		ptable += "[!] Access-Control-Allow-Methods Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Control-Allow-Methods Header found")
		ptable += "[i] Access-Control-Allow-Methods Header found\n"
	if "access-control-allow-headers" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Allow-Headers Header not found")
		ptable += "[!] Access-Control-Allow-Headers Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] "+ bcolors.ENDC +"Access-Control-Allow-Headers Header found")
		ptable += "[i] Access-Control-Allow-Headers Header found\n"
	if "access-control-request-method" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Request-Method Header not found")
		ptable += "[!] Access-Control-Request-Method Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] "+ bcolors.ENDC+"Access-Control-Request-Method Header found")
		ptable += "[i] Access-Control-Request-Method Header found\n"
	if "access-control-request-headers" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Access-Control-Request-Headers Header not found")
		ptable += "[!] Access-Control-Request-Headers Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Control-Request-Headers Header found")
		ptable += "[i] Access-Control-Request-Headers Header found\n"
	if "access-content-policy-security" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] "+ bcolors.ENDC+"Access-Content-Policy-Security Header not found" )
		ptable += "[-] Access-Content-Policy-Security Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Access-Content-Policy-Security Header found")
		ptable += "[i] Access-Content-Policy-Security Header found\n"
	if "strict-transport-security" not in cabecera.lower():
		cont += 1
		print(bcolors.RED + "\t[!] " + bcolors.ENDC+"Strict-Transport-Security Header not found\n"+bcolors.RED + "\tDescription:" +bcolors.ENDC + "\n\tHTTP Strict Transport Security is an excellent feature to support on your site and strengthens\n\tyour implementation of TLS by getting the User Agent to enforce the use of HTTPS.\n\tRecommended value \"strict-transport-security: max-age=31536000; includeSubDomains\".\n")
		ptable += "[-] Strict-Transport-Security Header not found\n"
	else:
		print(bcolors.GREEN + "\t[i] " + bcolors.ENDC+"Strict-Transport-Security Header found")
		ptable += "[-] Strict-Transport-Security Header found\n"
	if cont == 0:
		print(bcolors.GREEN + "\t[+] The HTTP Headers are correct" + bcolors.ENDC)
	print(bcolors.BLUE + "[*] " + bcolors.ENDC+"Analyzing Cookies")
	if "cookie" in cabecera.lower():
		if "expires" in cabecera.lower():
			print(bcolors.YELLOW + "\t[#] " + bcolors.ENDC+"Check cookie expiration!")
			pcookies += "[!]  Check cookie expiration!\n"
		if "httponly" not in cabecera.lower():
			print(bcolors.RED +"\t[!] " + bcolors.ENDC+"'HTTPOnly' Attribute (cookie) not found")
			pcookies += "[!]  'HTTPOnly' Attribute (cookie) not found\n"
		else:
			print(bcolors.GREEN +"\t[i] " + bcolors.ENDC+"'HTTPOnly' Attribute (cookie) found")
			pcookies += "[i]  'HTTPOnly' Attribute (cookie) found\n"
		if "secure" not in cabecera.lower():
			print(bcolors.RED + "\t[!] " + bcolors.ENDC+"'Secure' Attribute (cookie) not found")
			pcookies += "[!]  'Secure' Attribute (cookie) not found\n"
		else:
			print(bcolors.GREEN +"\t[i] " + bcolors.ENDC+"'Secure' Attribute (cookie) found")
			pcookies += "[i]  'Secure' Attribute (cookie) found\n"
		if "path=/'" in cabecera or 'path=/;' in cabecera:
			print(bcolors.RED + "\t[!] " + bcolors.ENDC+"'Path' Attribute (cookie) found but is wrong")
			pcookies += "[-]  'Path' Attribute (cookie) found but is wrong\n"
		else:
			 print(bcolors.GREEN + "\t[i]" + bcolors.ENDC+"'Path' Attribute (cookie) correct")
			 pcookies += "[i]  'Path' Attribute found and is correct \n"
	else:
		print(bcolors.GREEN + "\t[i] No cookies found\n" + bcolors.ENDC)
		pcookies += "[+]  No cookies found"

	if "access-control-allow-methods" in cabecera.lower():
		print(bcolors.RED + "[!] " + bcolors.ENDC+"Check allow methods EX: HEAD, GET,POST, DELETE... \n")
	if "akamai" in cabecera.lower():
		print(bcolors.HEADER + "[-] " + bcolors.ENDC+"Akamai Detected \n" + bcolors.ENDC)
		pfinger += "[-] Akami Detected\n"
	if "x-cdn-pop-ip" in cabecera.lower() or "ovhcdn" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" OVH Server Detected\n")
		pfinger += "[-] OVH Server Detected\n"
	if "x-cdn-geo" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" OVH Server Location found\n")
		pfinger += "[-] OVH Server Location found\n"
	if "x-github-request-id" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" GitHub Server Location found\n")
		pfinger += "[-] GitHub Server Location found\n"
	if "x-powered-by" in cabecera.lower() or 'powered' in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" X-Powered-By Detected \n")
		pfinger += "[-] X-Powered-By Detected\n"
	if "cloudflare" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" CloudFlare Detected \n")
		pfinger += "[-] CloudFlare Detected\n"
	if "cloudfront" in cabecera.lower():
		print(bcolors.HEADER + "[-]"+ bcolors.ENDC+" CloudFront Detected \n")
		pfinger += "[-] CloudFront Detected\n"
	if "ubuntu" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Ubuntu Detected \n")
		pfinger += "[-] Ubuntu Detected\n"
	if "debian" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Debian Detected \n")
		pfinger += "[-] Debian Detected\n"
	if "red hat" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Red Hat Detected \n")
		pfinger += "[-] Red Hat Detected\n"
	if "windows" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Windows Detected \n")
		pfinger += "[-] Windows Detected\n"
	if "microsoft" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" System of Microsoft Detected \n")
		pfinger += "[-] System of Microsoft Detected\n"
	if "origin" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Origin Header Detected \n")
		pfinger += "[-] Origin Header Detected\n"
	if "lighttpd" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Lighttpd Detected \n")
		pfinger += "[-] Lighttpd Detected\n"
	if "litespeed" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" LiteSpeed Detected \n")
		pfinger += "[-] LiteSpeed Detected\n"
	if "microsoft-httpapi/2.0" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Microsoft-HTTPAPI/2.0 Detected \n")
		pfinger += "[-] Microsoft-HTTPAPI/2.0 Detected\n"
	if "ats" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" ATS Detected \n")
		pfinger += "[-] ATS Detected\n"
	if "varnish" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Varnish Detected \n")
		pfinger += "[-] Varnish Detected\n"
	if "cdn" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" CDN Detected \n")
		pfinger += "[-] CDN Detected\n"
	if "alibaba" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Alibaba Detected \n")
		pfinger += "[-] Alibaba Detected\n"
	if "azure" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Azure Detected \n")
		pfinger += "[-] Azure Detected\n"
	if "fastly" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Fastly Detected \n")
		pfinger += "[-] Fastly Detected\n"
	if "level3" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Level3 Detected \n")
		pfinger += "[-] Level3 Detected\n"
	if "tencent" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Tencent Detected \n")
		pfinger += "[-] Tencent Detected\n"
	if "bitdefender" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Bitdefender Detected (Probably Firewall)\n")
		pfinger += "[-] Bitdefender Detected (Probably Firewall)\n"
	if "eset" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" ESET Detected (Probably Firewall)\n")
		pfinger += "[-] ESET Detected (Probably Firewall)\n"
	if "huawei" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Huawei Detected (Probably Firewall) \n")
		pfinger += "[-] Huawei Detected (Probably Firewall)\n"
	if "kaspersky" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Kaspersky Detected (Probably Firewall)\n")
		pfinger += "[-] Kaspersky Detected (Probably Firewall)\n"
	if "pan" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" PAN Detected (Probably Firewall)\n")
		pfinger += "[-] PAN Detected (Probably Firewall)\n"
	if "forti" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Forti* Product Detected \n")
		pfinger += "[-] Forti* Product Detected \n"
	if "proxy" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Proxy Detected \n")
		pfinger += "[-] Proxy Detected \n"
	if "x-wix-renderer-server" in cabecera.lower() or "x-wix-request-id" in cabecera.lower():	
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Webpage Created with Wix \n")
		pfinger += "[-] Webpage Created with Wix\n"
	if "asp" in cabecera.lower():
		print(bcolors.HEADER + "[-]"+ bcolors.ENDC+" ASP running\n" )
		pfinger += "[-] ASP running\n"
	if "iis" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" IIS Server running\n")
		pfinger += "[-] IIS Server running\n"
	if "jsf" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" JSF running\n")
		pfinger += "[-] JSF running\n"
	if "apache" in cabecera.lower():
		if "coyote" in cabecera.lower():
			print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Apache Coyote (Tomcat), Java Server running\n")
			pfinger += "[-] Apache Coyote (Tomcat), Java Server running\n"
		elif "tomcat" in cabecera.lower():
			print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Apache Tomcat, Java Server running\n")
			pfinger += "[-] Apache Tomcat, Java Server running\n"
		else:
			print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Apache Server running\n")
			pfinger += "[-] Apache Server running\n"
	if "squid" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Squid running\n")
		pfinger += "[-] Squid running\n"
	if "openresty" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" OpenResty running\n")
		pfinger += "[-] OpenResty running\n"
	if "nginx" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Nginx Server running\n")
		pfinger += "[-] Nginx Server running\n"
	if "hhvm" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Created with HHVM\n")
		pfinger += "[-] Created with HHVM\n"
	if "pepyaka" in cabecera.lower():
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" Pepyaka Server running, (Probably a Wix Russian Server)\n")
		pfinger += "[-] Pepyaka Server running, (Probably a Wix Russian Server)\n"
	regexp = re.compile("PHP\/|\' ")
	if regexp.search(cabecera) is not None:
		print(bcolors.HEADER + "[-]" + bcolors.ENDC+" PHP running\n")
		pfinger += "[-] PHP running\n"
		
	report("HTTP Headers","Analyzing headers",ptable)
	report("Cookies","Analyzing Cookies",pcookies)
	report("Manual check","Manual check:",cabecera)
	report("Fingerprint","Fingerprint(Information:",pfinger)

	regexp = re.compile("PHP\/|\' ")
	if regexp.search(cabecera) is not None:
		regex = "[PHP]+\/[0-9]+\.[0-9]+\.+[^\ \']+[^\ \']"
	if "apache" in cabecera.lower():
		if "coyote" in cabecera.lower():
			regex = "[a-zA-Z]+\-+[a-zA-Z]+\/[0-9]+\.[0-9]+(.[0-9]+|)"
		elif "tomcat" in cabecera.lower():
			regex = "[a-zA-Z]+\-+[a-zA-Z]+\/[0-9]+\.[0-9]+(.[0-9]+|)"
		else:
			regex = ".[pache]+\/[0-9]+\.[0-9]+\.+[^\ \']"
	if "squid" in cabecera.lower():
		regex = ".[quid]+\/[0-9]+\.[0-9]+"
	if "jsf" in cabecera.lower():
		regex = ".[sf]+\/[0-9]+\.[0-9]+"
	if "nginx" in cabecera.lower():
		regex = ".[ginx]+\/[0-9]+\.[0-9]+\.+[^\ \']"
	if "hhvm" in cabecera.lower():
		regex = "[a-zA-Z]+\/[0-9]+\.[0-9]+\.[0-9]"
	if "pepyaka" in cabecera.lower():
		regex = ".[epyaka]+\/[0-9]+\.[0-9]+\.+[^\ \']"


ascii()
if (len(sys.argv) == 1):
	print(bcolors.RED+"[!] Enter a valid URL"+bcolors.ENDC)
	print(bcolors.GREEN+"Ex: python crosshead.py http://google.es"+bcolors.ENDC)
	print(bcolors.BLUE+"[#] Options available:")
	print("	--proxy (Use proxy for your connections, editing it before in the code)")
	print("	--proxy-tor (Use TOR proxy for your connections)")
	print("	--verify (Verify SSL Certificate, value for default: false)")
	print("\t\tNOTE: This option don't force the SSL protocol, only verify the certified")
	print("	--report-advanced Create a MD advanced report"+bcolors.ENDC)
else:
	try:
		url = sys.argv[1]
		advanced_b = False
		if url[:4] != "http":
			url="http://"+url 
			print(bcolors.RED+"[-] "+bcolors.ENDC + "Added HTTP for your URL, remember, change it for https if is need it.")
		verif = False
		execut = False
		if url.startswith("https"):
			print(bcolors.GREEN+"[i] " +bcolors.ENDC + "Nice! Your web have SSL")
			sslinfo = "[i] Nice! Your web have SSL"
		else:
			print(bcolors.RED+"[-] "+bcolors.ENDC + "Ouch! Your web don't have SSL, you should report this")
			sslinfo = "[-] Ouch! Your web don't have SSL"

		if (len(sys.argv) > 2):
			if ("--verify" in sys.argv):
				print(bcolors.BLUE+"[$] "+bcolors.ENDC+"Verify loaded succesfully\n")
				verif = True
				execut = True

			if ("--proxy" in sys.argv):
				print(bcolors.BLUE+"[$] "+bcolors.ENDC+ "Proxy loaded succesfully\n")
				http_proxy  = "http://127.0.0.1:8080"
				https_proxy = "http://127.0.0.1:8080"
				proxyDict = { 
					"http"  : http_proxy, 
					"https" : https_proxy,
				}
				
				if (verif == True):
					r = requests.get(url,proxies=proxyDict,verify=True)
					execut = False
				
				if (verif == False):
					r = requests.get(url,proxies=proxyDict,verify=False)
					execut = False
			
			if ("--proxy-tor" in sys.argv):
				print(bcolors.BLUE+"[$] "+bcolors.ENDC+"TOR Proxy loaded succesfully\n")
				http_proxy  = "http://127.0.0.1:9050"
				https_proxy = "http://127.0.0.1:9050"
				proxyDict = { 
					"http"  : http_proxy, 
					"https" : https_proxy,
				}
				
				if (verif == True):
					r = requests.get(url,proxies=proxyDict,verify=True)
					execut = False
				
				if (verif == False):
					r = requests.get(url,proxies=proxyDict,verify=False)
					execut = False
			
			if (execut == True):
				r = requests.get(url,verify=True)

			if ("--report-advanced" in sys.argv):
				advanced_b = True
				r = requests.get(url,verify=False)
			else:
				advanced_b = False
		else:
			r = requests.get(url,verify=False)
					
		
		print(bcolors.BLUE+"[*] "+  bcolors.ENDC+"Analyzing URL " + bcolors.BLUE + str(url) + bcolors.ENDC)
		if (r.status_code == 200):
			print(bcolors.BLUE+"[*] "+ bcolors.ENDC+"Status: " + bcolors.GREEN+ str(r.status_code) + bcolors.ENDC +" ("+ r.reason + ")\n")
		else:
			print(bcolors.BLUE+"[*] "+ bcolors.ENDC+"Status: " + bcolors.RED+ str(r.status_code) + bcolors.ENDC +" ("+ r.reason + ")\n")
		if str(r.reason) == "OK":
			print(bcolors.BLUE+"[*] "+bcolors.ENDC+"Wait please...\n")
			print(bcolors.GREEN+"[i] "+bcolors.ENDC+"Creating report in this directory with name Fingerprint.md.\n")
		else:
			print(bcolors.BLUE+"[*] "+bcolors.ENDC+ "Check Status Code!\n")
			print(bcolors.GREEN+"[i] "+bcolors.ENDC+"Creating report in this directory with name Fingerprint.md but you should check the status code.\n")
			print(bcolors.BLUE+"[*] "+bcolors.ENDC+"Wait please...\n")
		if (advanced_b == True):
			print(bcolors.GREEN+"[i] "+bcolors.ENDC+"Creating advanced report in this directory with name Advanced-Report.md.\n")
			advanced_report(url)
		report("Target","Target info:","URL:" + url+"\n"+sslinfo)
		
		cabecera = str(r.headers)
		cms_identifier(str(url),r)
		analyze(cabecera)
	except Exception as e:
			print(e)
