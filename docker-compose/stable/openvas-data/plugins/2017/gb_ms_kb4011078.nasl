###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Outlook 2013 Service Pack 1 Multiple Vulnerabilities (KB4011078)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811262");
  script_version("2020-10-27T15:01:28+0000");
  script_cve_id("CVE-2017-8571", "CVE-2017-8572", "CVE-2017-8663");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-07-28 15:59:49 +0530 (Fri, 28 Jul 2017)");
  script_name("Microsoft Outlook 2013 Service Pack 1 Multiple Vulnerabilities (KB4011078)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011078");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when Microsoft Office Outlook improperly handles input.

  - An error when Microsoft Office improperly discloses the contents of its memory.

  - An error in the way that Microsoft Outlook parses specially crafted email
    messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary commands, gain access to potentially sensitive
  information and bypass certain security restrictions.");

  script_tag(name:"affected", value:"Microsoft Outlook 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011078");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");
if(!outlookVer || outlookVer !~ "^15\."){
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer){
  exit(0);
}

if(version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.4953.1000"))
{
  report = 'File checked:     ' +  outlookFile + "\outlook.exe" + '\n' +
           'File version:     ' +  outlookVer  + '\n' +
           'Vulnerable range:  15.0 - 15.0.4953.1000'+ '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
