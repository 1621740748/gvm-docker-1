###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visual Studio 2013 Update 5 Information Disclosure Vulnerability (KB4089283)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813141");
  script_version("2021-06-23T11:00:26+0000");
  script_cve_id("CVE-2018-1037");
  script_bugtraq_id(103715);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-04-18 14:21:17 +0530 (Wed, 18 Apr 2018)");
  script_name("Microsoft Visual Studio 2013 Update 5 Information Disclosure Vulnerability (KB4089283)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4089283");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Visual Studio improperly
  discloses limited contents of uninitialized memory while compiling program
  database (PDB) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2013 Update 5.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4089283");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_mandatory_keys("Microsoft/VisualStudio/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

vsVer = get_kb_item("Microsoft/VisualStudio/Ver");
if(!vsVer || vsVer !~ "^12\."){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\VisualStudio\12.0");
}

else if("x64" >< os_arch){
 key_list = make_list("SOFTWARE\Microsoft\VisualStudio\12.0", "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0");
}

foreach key (key_list)
{
  installPath = registry_get_sz(key:key, item:"ShellFolder");
  if(!installPath){
    continue;
  }

  binPath = installPath + "VC\bin";
  dllVer = fetch_file_version(sysPath:binPath, file_name:"mspdbsrv.exe");
  if(dllVer && dllVer =~ "^12\.0" && version_is_less(version:dllVer, test_version:"12.0.40669.0"))
  {
    report = report_fixed_ver(file_checked: binPath + "\mspdbsrv.exe",
                              file_version:dllVer, vulnerable_range:"12.0 - 12.0.40668");
    security_message(data:report);
    exit(0);
  }
}
exit(0);
