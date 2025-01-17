###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Products Guest Privilege Escalation Vulnerability - Nov09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801142");
  script_version("2020-12-08T13:28:48+0000");
  script_tag(name:"last_modification", value:"2020-12-08 13:28:48 +0000 (Tue, 08 Dec 2020)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2267");
  script_bugtraq_id(36841);
  script_name("VMware Products Guest Privilege Escalation Vulnerability - Nov09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37172");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3062");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023082.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000069.html");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0015.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"impact", value:"Local attacker can exploit this issue to gain escalated privileges in a guest
  virtual machine.");

  script_tag(name:"affected", value:"VMware ACE version 2.5.x prior to 2.5.3 Build 185404,
  VMware Server version 2.0.x prior to 2.0.2 Build 203138,
  VMware Server version 1.0.x prior to 1.0.10 Build 203137,
  VMware Player version 2.5.x prior to 2.5.3 Build 185404,
  VMware Workstation version 6.5.x prior to 6.5.3 Build 185404 on Windows.");

  script_tag(name:"insight", value:"An error occurs while setting the exception code when a '#PF' (page fault)
  exception arises which can be exploited to gain escalated privileges within VMware guest.");

  script_tag(name:"solution", value:"Upgrade your VMWare according to the referenced vendor advisory.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) and is prone to
  Privilege Escalation vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed"))
  exit(0);

# VMware Player
vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer) {
  if(version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.2")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer) {
  if(version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.2")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer) {
  if(version_in_range(version:vmserverVer, test_version:"1.0", test_version2:"1.0.9") ||
     version_in_range(version:vmserverVer, test_version:"2.0", test_version2:"2.0.1")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware ACE
aceVer = get_kb_item("VMware/ACE/Win/Ver");
if(!aceVer)
  aceVer = get_kb_item("VMware/ACE\Dormant/Win/Ver");

if(aceVer) {
  if(version_in_range(version:aceVer, test_version:"2.5", test_version2:"2.5.2")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
