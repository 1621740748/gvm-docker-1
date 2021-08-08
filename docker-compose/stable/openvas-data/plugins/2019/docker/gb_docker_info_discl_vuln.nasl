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

CPE = "cpe:/a:docker:docker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142670");
  script_version("2021-04-21T07:59:45+0000");
  script_tag(name:"last_modification", value:"2021-04-21 07:59:45 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2019-07-29 04:04:50 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-13509");
  script_bugtraq_id(109253);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Docker < 18.09.8 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_http_rest_api_detect.nasl", "gb_docker_ssh_login_detect.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"Docker is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"Docker Engine in debug mode may sometimes add secrets to the
  debug log. This applies to a scenario where docker stack deploy is run to redeploy a stack that
  includes (non external) secrets. It potentially applies to other API users of the stack API if
  they resend the secret.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Docker prior to version 18.09.8.");

  script_tag(name:"solution", value:"Update to version 18.09.8 or later.");

  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "18.09.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.09.8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);