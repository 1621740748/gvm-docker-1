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
  script_oid("1.3.6.1.4.1.25623.1.0.902942");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-1313");
  script_bugtraq_id(57863);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-02-13 06:09:30 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft OLE Automation Remote Code Execution Vulnerability (2802968)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2802968");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028118");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-020");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code.");

  script_tag(name:"affected", value:"Microsoft Windows XP x32 Service Pack 3 and prior.");

  script_tag(name:"insight", value:"The flaw is due to memory allocation error in Microsoft Windows Object
  Linking and Embedding (OLE) Automation, This can be exploited to execute
  arbitrary code on the target system.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-020.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Oleaut32.dll");
if(!exeVer){
  exit(0);
}

if(version_is_less(version:exeVer, test_version:"5.1.2600.6341")){
  report = report_fixed_ver(installed_version:exeVer, fixed_version:"5.1.2600.6341", install_path:sysPath);
  security_message(port: 0, data: report);
}
