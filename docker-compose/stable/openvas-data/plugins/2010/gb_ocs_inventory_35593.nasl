###############################################################################
# OpenVAS Vulnerability Test
#
# OCS Inventory NG Agent 'Backend.pm' Perl Module Handling Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100868");
  script_version("2020-10-06T09:42:44+0000");
  script_bugtraq_id(35593);
  script_cve_id("CVE-2009-0667");
  script_tag(name:"last_modification", value:"2020-10-06 09:42:44 +0000 (Tue, 06 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-10-25 12:51:03 +0200 (Mon, 25 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("OCS Inventory NG Agent 'Backend.pm' Perl Module Handling Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/35593");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506416");
  script_xref(name:"URL", value:"http://www.ocsinventory-ng.org/index.php?mact=News,cntnt01,detail,0&cntnt01articleid=144&cntnt01returnid=64");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"OCS Inventory NG Agent is prone to a vulnerability that lets local
  attackers execute arbitrary Perl code.");

  script_tag(name:"impact", value:"Local attackers can leverage this issue to execute arbitrary code via
  the application's insecure Perl module search path. This may allow attackers to elevate their privileges
  and compromise the application or the underlying computer. Other attacks may also be possible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_equal(version: vers, test_version: "0.0.9.2") ||
    version_is_equal(version: vers, test_version: "1.00")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "See reference", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
