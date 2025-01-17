##############################################################################
# OpenVAS Vulnerability Test
# OpenSSL Multiple Vulnerabilities - 19 Jun16 (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107015");
  script_version("2021-03-10T05:21:16+0000");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-10 05:21:16 +0000 (Wed, 10 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-06-29 12:46:24 +0530 (Wed, 29 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("OpenSSL Multiple Vulnerabilities -19 Jun16 (Linux)");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  1. Incorrectly using of pointer arithmetic for heap-buffer boundary checks which might allow remote attackers to cause a denial of service or possibly
   have unspecified other impact by leveraging unexpected malloc behavior, related to s3_srvr.c, ssl_sess.c, and t1_lib.c.

  2. Improperly use of constant-time operations in crypto/dsa/dsa_oss.c which allow local users to breach the DSA private key.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of service and will allow local users to discover a DSA private key
  via a timing side-channel attack.");

  script_tag(name:"affected", value:"OpenSSL 1.0.2h and previous versions.");

  script_tag(name:"solution", value:"For the undefined pointer arithmetic vulnerability, there is a fix available for OpenSSL 1.0.2 and OpenSSL 1.0.1.
  To prevent DSA private key breach, a fix is available, too.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/blog/blog/2016/06/27/undefined-pointer-arithmetic/");
  script_xref(name:"URL", value:"https://git.openssl.org/?p=openssl.git;a=commit;h=399944622df7bd81af62e67ea967c470534090e2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.openssl.org/blog/blog/2016/06/27/undefined-pointer-arithmetic/");

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

if(vers =~ "^1\.0\.2" && version_is_less_equal(version:vers, test_version:"1.0.2h")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
