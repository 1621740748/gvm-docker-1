###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Compatibility Pack Service Pack 3 Multiple Vulnerabilities (KB4011265)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812123");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2017-11854");
  script_bugtraq_id(101746);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-11-15 00:24:36 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Office Compatibility Pack Service Pack 3 Multiple Vulnerabilities (KB4011265)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011265");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The software fails to properly handle objects in memory.

  - Microsoft has released an update for Microsoft Office that provides enhanced
    security as a defense-in-depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011265");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/WordCnv/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!path){
  exit(0);
}

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.")
{
  wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
  if(wordcnvVer && wordcnvVer =~ "^12\.")
  {
    offpath = path + "\Microsoft Office\Office12";

    sysVer = fetch_file_version(sysPath:offpath, file_name:"wordcnv.dll");
    if(sysVer && sysVer =~ "^12\.")
    {
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6780.4999"))
      {
        report = report_fixed_ver(file_checked:offpath + "\wordcnv.dll",
                                  file_version:sysVer, vulnerable_range:"12.0 - 12.0.6780.4999");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(0);
