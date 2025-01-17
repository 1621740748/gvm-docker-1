###############################################################################
# OpenVAS Vulnerability Test
#
# Elastic Kibana Cross-site Request Forgery (CSRF) Vulnerability (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808501");
  script_version("2021-01-18T09:33:18+0000");
  script_cve_id("CVE-2015-8131");
  script_bugtraq_id(77657);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-01-18 09:33:18 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2016-06-28 16:01:44 +0530 (Tue, 28 Jun 2016)");
  script_name("Elastic Kibana Cross-site Request Forgery (CSRF) Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Elastic Kibana
  and is prone to Cross-site Request Forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to an improper validation
  in the administrative console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack the authentication of unspecified victims.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elastic Kibana version before 4.1.3 and
  4.2.x before 4.2.1 on Linux.");

  script_tag(name:"solution", value:"Update to Elastic Kibana version 4.1.3,
  or 4.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/blog/kibana-4-2-1-and-4-1-3");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536935/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!kibanaPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!kibanaVer = get_app_version(cpe:CPE, port:kibanaPort)){
 exit(0);
}

if(version_is_less(version:kibanaVer, test_version:"4.1.3"))
{
  fix = "4.1.3";
  VULN = TRUE;
}

else if(version_is_equal(version:kibanaVer, test_version:"4.2.0"))
{
  fix = "4.2.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:fix);
  security_message(data:report, port:kibanaPort);
  exit(0);
}
