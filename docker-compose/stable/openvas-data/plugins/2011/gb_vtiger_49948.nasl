###############################################################################
# OpenVAS Vulnerability Test
#
# vtiger CRM 'onlyforuser' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:vtiger:vtiger_crm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103288");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)");
  script_cve_id("CVE-2011-4559");
  script_bugtraq_id(49948);

  script_name("vtiger CRM 'onlyforuser' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49948");
  script_xref(name:"URL", value:"https://secure.wikimedia.org/wikipedia/en/wiki/Vtiger_CRM");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/%5BvTiger_5.2.1%5D_blind_sqlin");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vtiger/detected");

  script_tag(name:"summary", value:"vtiger CRM is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"vtiger CRM 5.2.1 is vulnerable. Prior versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version: vers, test_version: "5.2.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
