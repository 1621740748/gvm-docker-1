###############################################################################
# OpenVAS Vulnerability Test
#
# IceWarp XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:icewarp:mail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140345");
  script_version("2020-11-05T10:18:37+0000");
  script_tag(name:"last_modification", value:"2020-11-05 10:18:37 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-09-01 15:42:08 +0700 (Fri, 01 Sep 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-7855");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IceWarp < 12.0.2.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_consolidation.nasl");
  script_mandatory_keys("icewarp/mailserver/http/detected");

  script_tag(name:"summary", value:"IceWarp is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"In the webmail component in IceWarp Server, there was an XSS vulnerability
  discovered in the 'language' parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 12.0.2.0 or later.");

  script_xref(name:"URL", value:"http://dl.icewarp.com/patchinfo/12.0.2.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "12.0.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
