###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Edge Multiple Vulnerabilities (3148532)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807540");
  script_version("2020-06-08T14:40:48+0000");
  script_cve_id("CVE-2016-0154", "CVE-2016-0155", "CVE-2016-0156", "CVE-2016-0157",
                "CVE-2016-0158", "CVE-2016-0161");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2016-04-13 08:13:24 +0530 (Wed, 13 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (3148532)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-038.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The Microsoft Edge improperly accesses objects in memory.

  - The Microsoft Edge does not properly enforce cross-domain policies.

  - The Microsoft Edge does not properly validate JavaScript under specific
  conditions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, gain sensitive information and could take
  control of an affected system.");

  script_tag(name:"affected", value:"- Microsoft Edge on Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3148532");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-038");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Edge/Installed");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.10240.16766"))
  {
    Vulnerable_range = "Less than 11.0.10240.16766";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.211"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.211";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
