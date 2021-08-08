###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Multiple Vulnerabilities-September18 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814206");
  script_version("2021-06-23T02:00:29+0000");
  script_cve_id("CVE-2018-8429", "CVE-2018-8331");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-09-12 15:30:55 +0530 (Wed, 12 Sep 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Multiple Vulnerabilities-September18 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 on Mac OSX according to Microsoft security
  update September 2018");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - when excel functions improperly handles objects in memory.

  - when the excel software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to sensitive information, run arbitrary code in the context of
  the current user and compromise the user's computer or data.");

  script_tag(name:"affected", value:"- Microsoft Office 2016 on Mac OS X

  - Microsoft Office 2019 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Microsoft Office 2016 version
  16.16.2 (Build 18091001) or Microsoft Office 2019 16.17.0 (Build 18090901)
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^1[5|6]\.)")
{
  if(version_is_less(version:offVer, test_version:"16.16.2"))
  {
    report = report_fixed_ver(installed_version:offVer, fixed_version:"16.16.3");
    security_message(data:report);
    exit(0);
  }
}
