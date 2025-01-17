# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903102");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2012-4575");
  script_bugtraq_id(56371);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-01-25 11:24:17 +0530 (Fri, 25 Jan 2013)");
  script_name("PostgreSQL PgBouncer Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51128");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79751");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/11/02/8");
  script_xref(name:"URL", value:"http://git.postgresql.org/gitweb/?p=pgbouncer.git;a=commit;h=4b92112b820830b30cd7bc91bef3dd8f35305525");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application
  to crash by creating a denial of service condition.");

  script_tag(name:"affected", value:"PostgreSQL PgBouncer Pooler version 1.5.2 and prior on Windows.");

  script_tag(name:"insight", value:"An error exists within the 'add_database' function in objects.c in the
  pgbouncer pooler when adding new databases with an overly large name.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL PgBouncer Pooler version 1.5.3 or later.");

  script_tag(name:"summary", value:"This host is installed with PostgreSQL PgBouncer pooler and is
  prone to a denial of service vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");

if(!get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

key = "SOFTWARE\EnterpriseDB\PgBouncer";
if(!registry_key_exists(key:key))
  exit(0);

vers = registry_get_sz(key:key, item:"Version");
if(!vers)
  exit(0);

if("-" >< vers)
  vers = str_replace(pattern:"-", string:vers, replace:".");

if(version_is_less(version:vers, test_version:"1.5.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.5.3", reg_checked:key + "!Version");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
