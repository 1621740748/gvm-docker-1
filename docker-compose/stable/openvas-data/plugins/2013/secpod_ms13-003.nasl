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
  script_oid("1.3.6.1.4.1.25623.1.0.903100");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-0009", "CVE-2013-0010");
  script_bugtraq_id(55408, 55401);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-01-09 10:25:58 +0530 (Wed, 09 Jan 2013)");
  script_name("MS System Center Operations Manager XSS Vulnerabilities (2748552)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78069");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/78070");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-003");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_scom_detect_win.nasl");
  script_mandatory_keys("MS/SCOM/Ver", "MS/SCOM/Path");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert script code
  or issue commands to the SCOM server, which will be executed in a user's
  browser session in the context of an affected site.");
  script_tag(name:"affected", value:"- Microsoft System Center Operations Manager 2007 R2

  - Microsoft System Center Operations Manager 2007 SP1");
  script_tag(name:"insight", value:"Input validation error due the way System Center Operations Manager
  handles specially crafted requests, which can be exploited to insert
  arbitrary HTML and script code.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-003.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

scom_name = get_kb_item("MS/SCOM/Ver");
if(!scom_name) exit(0);

if("System Center Operations Manager 2007" >< scom_name)
{
  scom_path = get_kb_item("MS/SCOM/Path");
  if(scom_path && "Could not find the install Location" >!< scom_path)
  {
    scom_exeVer = fetch_file_version(sysPath: scom_path, file_name:"Microsoft.Mom.ConfigServiceHost.exe");
    if(scom_exeVer)
    {
      if(version_in_range(version:scom_exeVer, test_version:"6.0.5000.0", test_version2:"6.0.6278.0")||
         version_in_range(version:scom_exeVer, test_version:"6.1.7221.0", test_version2:"6.1.7221.109"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
