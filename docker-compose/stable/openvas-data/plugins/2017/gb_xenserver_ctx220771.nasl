###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix XenServer Multiple Security Updates (CTX220771)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140173");
  script_cve_id("CVE-2017-2615", "CVE-2017-2620");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2020-04-02T13:53:24+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX220771)");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220771");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"Two security issues have been identified within Citrix XenServer.");

  script_tag(name:"impact", value:"These issues could, if exploited, allow the administrator of an HVM guest VM to compromise the host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2017-2615 (High): QEMU: oob access in cirrus bitblt copy

  - CVE-2017-2620 (High): QEMU: cirrus_bitblt_cputovideo does not check if memory region is safe.

  Customers using only PV guest VMs are not affected by this vulnerability.

  Customers using only VMs that use the std-vga graphics emulation are not affected by this vulnerability.");

  script_tag(name:"affected", value:"XenServer 7.0

  XenServer 6.5

  XenServer 6.2.0

  XenServer 6.0.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2020-04-02 13:53:24 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-02-22 14:10:53 +0100 (Wed, 22 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("citrix_version_func.inc");
include("host_details.inc");
include("list_array_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") )
  exit( 0 );

patches = make_array();

patches['7.0.0'] = make_list( 'XS70E029' );
patches['6.5.0'] = make_list( 'XS65ESP1050' );
patches['6.2.0'] = make_list( 'XS62ESP1057' );
patches['6.0.2'] = make_list( 'XS602ECC041' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
