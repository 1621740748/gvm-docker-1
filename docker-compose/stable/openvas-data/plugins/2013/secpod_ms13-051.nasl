# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902976");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-1331");
  script_bugtraq_id(60408);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-06-12 09:09:10 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (2839571)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2817421");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028650");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-051");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.");

  script_tag(name:"affected", value:"Microsoft Office 2003 Service Pack 3.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing PNG files and can be exploited
  to cause a buffer overflow via a specially crafted file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-051.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2003
if(!officeVer || officeVer !~ "^11\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(!path){
  exit(0);
}

offPath = path + "\Microsoft Shared\OFFICE11";
dllVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8402"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
