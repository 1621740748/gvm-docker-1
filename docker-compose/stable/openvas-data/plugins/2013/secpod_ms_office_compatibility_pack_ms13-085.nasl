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
  script_oid("1.3.6.1.4.1.25623.1.0.903410");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-3889", "CVE-2013-3890");
  script_bugtraq_id(62829, 62824);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-10-09 11:13:35 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (2885080)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-085.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws are due to error when processing Microsoft Word binary
  documents can be exploited to cause a memory corruption");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2827326");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-085");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^12\.")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6683.5001"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}