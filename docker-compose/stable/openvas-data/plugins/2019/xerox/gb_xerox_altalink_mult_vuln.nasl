##############################################################################
# OpenVAS Vulnerability Test
#
# Xerox AltaLink Printers Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141826");
  script_version("2020-05-06T10:58:02+0000");
  script_tag(name:"last_modification", value:"2020-05-06 10:58:02 +0000 (Wed, 06 May 2020)");
  script_tag(name:"creation_date", value:"2019-01-04 15:55:04 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-2109", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2176", "CVE-2016-2107",
                "CVE-2018-17172");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox AltaLink Printers Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox_printer/detected");

  script_tag(name:"summary", value:"Xerox AltaLink Printers are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Xerox AltaLink Printers are prone to multiple vulnerabilities:

  - Reflective cross site scripting vulnerability (XSS)

  - Additional other cross site scripting vulnerabilities (XSS)

  - Vulnerabilities found in OpenSSL (CVE-2016-2109, CVE-2016-2105, CVE-2016-2106, CVE-2016-2176, CVE-2016-2107)

  - Unauthenticated command injection in the web application interface (CVE-2018-17172)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"affected", value:"Xerox AltaLink B80xx, C8030, C8035, C8045, C8055 and C8070 prior to
  firmware version 100.008.028.05200.");

  script_tag(name:"solution", value:"Update to version 100.008.028.05200 or later.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2018/12/cert_Security_Mini_Bulletin_XRX18AL_for_ALB80xx-C80xx_v1.1.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:altalink_b8045_firmware",
                     "cpe:/o:xerox:altalink_b8055_firmware",
                     "cpe:/o:xerox:altalink_b8065_firmware",
                     "cpe:/o:xerox:altalink_b8075_firmware",
                     "cpe:/o:xerox:altalink_b8090_firmware",
                     "cpe:/o:xerox:altalink_c8030_firmware",
                     "cpe:/o:xerox:altalink_c8035_firmware",
                     "cpe:/o:xerox:altalink_c8045_firmware",
                     "cpe:/o:xerox:altalink_c8055_firmware",
                     "cpe:/o:xerox:altalink_c8070_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "100.008.028.05200")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "100.008.028.05200");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
