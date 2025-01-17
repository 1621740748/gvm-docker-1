# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900212");
  script_version("2019-12-17T13:35:01+0000");
  script_tag(name:"last_modification", value:"2019-12-17 13:35:01 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_bugtraq_id(31009);
  script_cve_id("CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");

  script_name("Wireshark Multiple Vulnerabilities - Sept-08 (Windows)");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This host is running Wireshark/Ethereal which is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Infinite loop errors in the NVP dissector

  - An error when uncompressing zlib-compressed packet data

  - An error when reading a Tektronix .rf5 file");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service
  condition or application crash by injecting a series of malformed
  packets or by convincing the victim to read a malformed packet.");

  script_tag(name:"affected", value:"Wireshark versions 1.0.2 and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to wireshark 1.0.3 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31674");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2493");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-05.html");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!version = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal", item:"DisplayVersion"))
  exit(0);

version = ereg_replace(pattern:"Ethereal (.*)", replace:"\1", string:version);

if(ereg(pattern:"^0\.(9\.[7-9]|10\.(0?[0-9]|1[0-3]))$",
  string:version)) {
  security_message(data:"The target host was found to be vulnerable");
} else if(ereg(pattern:"^0\.(10\.14|99\.0)$",
  string:version)) {
  security_message(data:"The target host was found to be vulnerable");
}

if(!version = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark", item:"DisplayVersion"))
  exit(0);

if(ereg(pattern:"^0\.99\.[1-5]$", string:version)) {
  security_message(data:"The target host was found to be vulnerable");
  exit(0);
} else if(ereg(pattern:"^(0\.99\.[6-9]|1\.0\.[0-2])$", string:version)) {
  security_message(data:"The target host was found to be vulnerable");
  exit(0);
}

exit(0);
