###############################################################################
# OpenVAS Vulnerability Test
#
# Centreon 'main.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:centreon:centreon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100570");
  script_version("2020-04-24T07:24:50+0000");
  script_tag(name:"last_modification", value:"2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)");
  script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1301");
  script_bugtraq_id(39118);

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Centreon 'main.php' SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39118");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("centreon_detect.nasl");
  script_mandatory_keys("centreon/installed");

  script_tag(name:"summary", value:"Centreon is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Centreon 2.1.5 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version: "2.1.5")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less or equal to 2.1.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
