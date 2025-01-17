###############################################################################
# OpenVAS Vulnerability Test
#
# Tenable Nessus '.nessus' files Stored Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807396");
  script_version("2019-12-18T08:33:37+0000");
  script_cve_id("CVE-2016-9260");
  script_bugtraq_id(95772);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-12-18 08:33:37 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2017-02-08 11:32:12 +0530 (Wed, 08 Feb 2017)");
  script_name("Tenable Nessus '.nessus' files Stored Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2016-16");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2017/JVNDB-2017-000013.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN12796388/index.html");

  script_tag(name:"summary", value:"This host is installed with Nessus and is prone to
  a stored Cross-Site Scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling
  of '.nessus' files, which allows attackers to execute arbitrary HTML and
  script code in the context of an affected application or site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Tenable Nessus versions prior to 6.9.");

  script_tag(name:"solution", value:"Upgrade Tenable Nessus to 6.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"6.9")) {
   report = report_fixed_ver(installed_version:vers, fixed_version:"6.9");
   security_message(port:port, data:report);
   exit(0);
}

exit(99);
