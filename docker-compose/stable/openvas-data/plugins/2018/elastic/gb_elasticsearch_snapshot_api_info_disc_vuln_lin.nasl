###############################################################################
# OpenVAS Vulnerability Test
#
# Elasticsearch '_snapshot API' Information Disclosure Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814076");
  script_version("2021-05-28T06:00:18+0200");
  script_cve_id("CVE-2018-3826");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-09 11:12:08 +0530 (Tue, 09 Oct 2018)");
  script_name("Elasticsearch '_snapshot API' Information Disclosure Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Elasticsearch and is prone
  to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when access_key
  and security_key parameters are set via the '_snapshot' API.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to query the _snapshot API and leak sensitive information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"affected", value:"Elasticsearch versions 6.0.0-beta1 to 6.2.4 on Linux.");
  script_tag(name:"solution", value:"Update to Elasticsearch version 6.3.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-3-0-and-5-6-10-security-update/135777");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(!esPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:esPort, exit_no_version:TRUE)) exit(0);
esVer = infos['version'];
esPath = infos['location'];

if(revcomp(a: esVer, b: "6.0.0-beta1") >= 0 && revcomp(a: esVer, b: "6.2.4") <= 0)
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"6.3.0", install_path:esPath);
  security_message(data:report, port:esPort);
  exit(0);
}
exit(99);
