###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress WooCommerce Plugin Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.112487");
  script_version("2020-08-11T08:45:26+0000");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-11 08:45:26 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-16 11:33:11 +0100 (Wed, 16 Jan 2019)");

  script_cve_id("CVE-2017-18356");

  script_name("WordPress WooCommerce Plugin Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"The WooCommerce Plugin for WordPress is prone to
  a privilege escalation vulnerability.

  This VT has been merged into the VT 'WordPress WooCommerce Plugin Privilege Escalation Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.112486).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attack is possible after gaining access to the target site with a
  user account that has at least Shop manager privileges. The attacker then constructs a specifically
  crafted string that will turn into a PHP object injection involving the includes/shortcodes/class-wc-shortcode-products.php WC_Shortcode_Products::get_products()
  use of cached queries within shortcodes.");

  script_tag(name:"affected", value:"WooCommerce plugin for WordPress prior to version 3.2.4 on Windows.

  Additionally this issue is only present in WordPress version >= 4.8.3.");

  script_tag(name:"solution", value:"Upgrade WooCommerce to version 3.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/woocommerce-php-object-injection/");
  script_xref(name:"URL", value:"https://woocommerce.wordpress.com/2017/11/16/woocommerce-3-2-4-security-fix-release-notes/");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
