###############################################################################
# OpenVAS Vulnerability Test
#
# HPE Sizer for Microsoft SharePoint Remote Arbitrary Code Execution Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809456");
  script_version("2020-05-15T08:09:24+0000");
  script_cve_id("CVE-2016-4377");
  script_bugtraq_id(92479);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-15 08:09:24 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2016-10-18 12:24:03 +0530 (Tue, 18 Oct 2016)");
  script_name("HPE Sizer for Microsoft SharePoint Remote Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE Sizer for
  Microsoft SharePoint and is prone to remote arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  arbitrary code execution.");

  script_tag(name:"affected", value:"HPE Sizer for Microsoft SharePoint prior to version 16.13.1");

  script_tag(name:"solution", value:"Upgrade to HPE Sizer for Microsoft
  SharePoint version 16.13.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05237578");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_sizer_microsoft_sharepoint_detect.nasl");
  script_mandatory_keys("HPE/sizer/microsoft/sharepoint/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:hp:sizer_for_microsoft_sharepoint_2010", "cpe:/a:hp:sizer_for_microsoft_sharepoint_2013");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if("cpe:/a:hp:sizer_for_microsoft_sharepoint_2010" >< cpe) {
  if(version_is_less(version:vers, test_version:"16.11.0")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.11.0", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

else if("cpe:/a:hp:sizer_for_microsoft_sharepoint_2013" >< cpe) {
  if(version_is_less(version:vers, test_version:"16.13.1")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.13.1", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
