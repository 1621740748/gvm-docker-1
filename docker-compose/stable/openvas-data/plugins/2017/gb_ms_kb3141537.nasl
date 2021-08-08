###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Publisher 2010 Service Pack 2 Remote Code Execution Vulnerability (KB3141537)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811756");
  script_version("2020-06-04T12:11:49+0000");
  script_cve_id("CVE-2017-8725");
  script_bugtraq_id(100758);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-04 12:11:49 +0000 (Thu, 04 Jun 2020)");
  script_tag(name:"creation_date", value:"2017-09-13 11:48:30 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Publisher 2010 Service Pack 2 Remote Code Execution Vulnerability (KB3141537)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3141537");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Microsoft
  Office software when it fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could use a specially crafted file
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Publisher 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3141537");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exeVer = get_kb_item("SMB/Office/Publisher/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Publisher/Installed/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

##Microsoft Publisher 2010
if(exeVer && exeVer =~ "^14.*")
{
  if(version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7188.4999"))
  {
     report = 'File checked:     ' + exePath + 'mspub.exe'  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + "14.0 - 14.0.7188.4999" + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
exit(0);
