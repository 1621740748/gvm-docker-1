# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117168");
  script_version("2021-01-19T14:54:13+0000");
  script_tag(name:"last_modification", value:"2021-01-19 14:54:13 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 14:15:51 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-3827");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Only repository-azure plugin affected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch < 6.3.0 Information Exposure Vulnerability (ESA-2018-11)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information exposure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A sensitive data disclosure flaw was found in the Elasticsearch
  repository-azure (formerly elasticsearch-cloud-azure) plugin.");

  script_tag(name:"impact", value:"When the repository-azure plugin is set to log at TRACE level Azure
  credentials can be inadvertently logged.");

  script_tag(name:"affected", value:"Elasticsearch prior to version 6.3.0.");

  script_tag(name:"solution", value:"Update to version 6.3.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-3-0-and-5-6-10-security-update/135777");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
