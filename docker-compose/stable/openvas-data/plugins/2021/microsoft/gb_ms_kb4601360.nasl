# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817595");
  script_version("2021-03-09T09:52:25+0000");
  script_cve_id("CVE-2021-1722", "CVE-2021-1727", "CVE-2021-1734", "CVE-2021-24074",
                "CVE-2021-24076", "CVE-2021-24077", "CVE-2021-24078", "CVE-2021-24079",
                "CVE-2021-24080", "CVE-2021-24083", "CVE-2021-24086", "CVE-2021-24088",
                "CVE-2021-24094", "CVE-2021-24102", "CVE-2021-24103", "CVE-2021-25195");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-09 09:52:25 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-02-10 09:31:47 +0530 (Wed, 10 Feb 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4601348)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4601348");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in Windows Fax Service.

  - An error in Windows Installer.

  - An error in Windows Remote Procedure Call.

  - An error in Windows TCP/IP.

  - An error in Microsoft Windows VMSwitch.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code on a victim system, disclose sensitive information,
  conduct denial-of-service condition and gain elevated privileges.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4601348");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"localspl.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.2.9200.23274"))
{
  report = report_fixed_ver(file_checked:dllPath + "\localspl.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.2.9200.23274");
  security_message(data:report);
  exit(0);
}
exit(99);
