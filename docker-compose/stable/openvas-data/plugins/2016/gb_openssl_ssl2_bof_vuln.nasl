###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSL SSL2 'KEY_ARG' Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810215");
  script_version("2021-03-10T05:21:16+0000");
  script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0659");
  script_bugtraq_id(5363, 5364, 5366);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-10 05:21:16 +0000 (Wed, 10 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-11-26 18:50:26 +0530 (Sat, 26 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL SSL2 <= 0.9.6d / 0.9.7 <= 0.9.7-beta2 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - an improper validation of 'KEY_ARG_LENGTH' parameter by the 'get_client_master_key' function in script
  'ssl/s2_srvr.c' during the handshake process with an SSL server connection using the SSLv2 communication
  process (CVE-2002-0656)

  - OpenSSL does not properly handle ASCII representations of integers on 64 bit platforms (CVE-2002-0655)

  - the ASN1 library in OpenSSL allows remote attackers to cause a denial of service via invalid
  encodings (CVE-2002-0659)");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to execute
  arbitrary code on the server or to cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSL versions 0.9.6d and earlier, and
  0.9.7-beta2 and earlier.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 0.9.6e or later
  or apply the patch provided by the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/102795");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40347");
  script_xref(name:"URL", value:"http://www.cert.org/historical/advisories/CA-2002-23.cfm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl");
  script_mandatory_keys("openssl/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"0.9.6e") ||
   version_is_equal(version:vers, test_version:"0.9.7-beta1") ||
   version_is_equal(version:vers, test_version:"0.9.7-beta2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.6e", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
