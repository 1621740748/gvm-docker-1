###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Domino iNotes Buffer Overflow Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803974");
  script_version("2020-09-22T09:01:10+0000");
  script_tag(name:"last_modification", value:"2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2013-12-05 17:56:32 +0530 (Thu, 05 Dec 2013)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2013-4068");
  script_bugtraq_id(62481);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Lotus Domino iNotes Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"IBM Lotus Domino is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino version 8.5.3 FP5 or 9.0 IF4 or later.");

  script_tag(name:"insight", value:"The flaw is in the iNotes. No much information is publicly available about this issue.");

  script_tag(name:"affected", value:"IBM Lotus Domino 8.5.3 before FP5 IF1 and 9.0 before IF4.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to crash the
  Domino server or execute arbitrary code.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86599");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21649476");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:version, test_version:"8.5.3.5") ||
   version_is_equal(version:version, test_version:"9.0.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.5.3 FP5 / 9.0 IF4");
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
