###############################################################################
# OpenVAS Vulnerability Test
#
# IBM iNotes Cross-Site Scripting Vulnerability-Aug17
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811269");
  script_version("2020-09-22T09:01:10+0000");
  script_tag(name:"last_modification", value:"2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2017-08-02 15:30:00 +0530 (Wed, 02 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-1332");
  script_bugtraq_id(100028);

  script_name("IBM iNotes Cross-Site Scripting Vulnerability - Aug17");

  script_tag(name:"summary", value:"IBM iNotes is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient sanitization
  of certain user input by the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow users to embed
  arbitrary JavaScript code in the Web UI thus altering the intended functionality
  potentially leading to credentials disclosure within a trusted session.");

  script_tag(name:"affected", value:"IBM iNotes version 8.5, 8.5.1, 8.5.2 and 8.5.3
  prior to 8.5.3 Fix Pack 6 Interim Fix 5, 9.0 and 9.0.1 prior to 9.0.1 Feature Pack 8 Interim Fix 3.");

  script_tag(name:"solution", value:"Upgrade to IBM iNotes 8.5.3 Fix Pack 6
  Interim Fix 5 or 9.0.1 Feature Pack 8 Interim Fix 3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22005233");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"9.0", test_version2:"9.0.1.8"))
  fix = "9.0.1 Feature Pack 8 Interim Fix 3";

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.6"))
  fix = "8.5.3 Fix Pack 6 Interim Fix 5";

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
