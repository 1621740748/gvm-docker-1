# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142410");
  script_version("2020-04-30T09:48:45+0000");
  script_tag(name:"last_modification", value:"2020-04-30 09:48:45 +0000 (Thu, 30 Apr 2020)");
  script_tag(name:"creation_date", value:"2019-05-15 08:05:42 +0000 (Wed, 15 May 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-10740");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.3.10 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"In Roundcube Webmail, an attacker in possession of S/MIME or PGP encrypted
  emails can wrap them as sub-parts within a crafted multipart email. The encrypted part(s) can further be hidden
  using HTML/CSS or ASCII newline characters. This modified multipart email can be re-sent by the attacker to the
  intended receiver. If the receiver replies to this (benign looking) email, they unknowingly leak the plaintext
  of the encrypted message part(s) back to the attacker.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Roundcube Webmail versions 1.3.9 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.10 or later.");

  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/issues/6638");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.3.10");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.3.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.10", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
