###############################################################################
# OpenVAS Vulnerability Test
#
# TCP/IP Predictable TCP Initial Sequence Number Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103701");
  script_version("2020-06-17T13:37:18+0000");
  script_bugtraq_id(670, 107);
  script_cve_id("CVE-1999-0077", "CVE-2000-0328", "CVE-2000-0916", "CVE-2001-0162", "CVE-2001-0288",
                "CVE-2001-0328", "CVE-2002-1463", "CVE-2003-1230", "CVE-2004-0641", "CVE-2007-2782",
                "CVE-2015-3963", "CVE-2018-7356");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-17 13:37:18 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"creation_date", value:"2013-04-22 11:14:29 +0200 (Mon, 22 Apr 2013)");
  script_name("TCP/IP Predictable TCP Initial Sequence Number Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  # nb: Set by nmap.nasl but adding a dependency to VT of the "ACT_SCANNER" VT is not allowed.
  # Please don't add such a dependency above.
  script_mandatory_keys("Host/tcp_seq");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/670");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/107");
  script_xref(name:"URL", value:"http://teso.scene.at/");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010301-ios-tcp-isn-random");
  script_xref(name:"URL", value:"ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-00:52.tcp-iss.asc");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-046");

  script_tag(name:"summary", value:"The remote host has predictable TCP sequence numbers.");

  script_tag(name:"impact", value:"An attacker may use this flaw to spoof TCP connections.");

  script_tag(name:"vuldetect", value:"Checks previous gathered info about the 'TCP sequence numbers' previously gathered
  by the VT 'Nmap (NASL wrapper)' (OID: 1.3.6.1.4.1.25623.1.0.14259).

  Note: This VT needs to be included in your scan configuration if you are not using the predefined 'Full and fast' or 'Full and very deep'
  scan configurations.");

  script_tag(name:"solution", value:"Update your OS to a more recent version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

tcp_seq = get_kb_item("Host/tcp_seq");
if(!tcp_seq)
  exit(0);

if(tcp_seq == "constant") {
  security_message(port:0, data:"The TCP sequence numbers of the remote host are constant.");
  exit(0);
}

else if(tcp_seq == "800") {
  security_message(port:0, data:"The TCP sequence numbers of the remote host are always incremented by 800, so they can be guessed rather easily.");
  exit(0);
}

else if(tcp_seq == "64000") {
  security_message(port:0, data:"The TCP sequence numbers of the remote host are always incremented by 64000, so they can be guessed rather easily.");
  exit(0);
}

else if(tcp_seq == "time") {
  security_message(port:0, data:"The TCP sequence numbers of the remote host depends on the time, so they can be guessed rather easily.");
  exit(0);
}

exit(99);
