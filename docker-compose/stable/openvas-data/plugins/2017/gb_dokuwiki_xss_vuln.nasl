##############################################################################
# OpenVAS Vulnerability Test
#
# DokuWiki XSS Vulnerability
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

CPE = 'cpe:/a:dokuwiki:dokuwiki';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140284");
  script_version("2020-11-12T08:54:04+0000");
  script_tag(name:"last_modification", value:"2020-11-12 08:54:04 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-08-08 14:37:42 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-12583");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DokuWiki XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_tag(name:"summary", value:"DokuWiki has a cross-site scripting vulnerability in the at parameter
(aka the DATE_AT variable) in doku.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"DokuWiki version 2017-02-19b and prior.");

  script_tag(name:"solution", value:"Update to version 2017-02-19e or later.");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/2061");
  script_xref(name:"URL", value:"https://www.dokuwiki.org/changes");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2017-02-19b")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2017-02-19e");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
