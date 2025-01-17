# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140035");
  script_version("2021-07-22T08:07:23+0000");
  script_tag(name:"last_modification", value:"2021-07-22 08:07:23 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-10-28 12:33:04 +0200 (Fri, 28 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-5300", "CVE-2012-0876");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("F5 BIG-IP - Expat XML library vulnerability CVE-2016-5300");

  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a vulnerability in the Expat XML library.

  This VT has been deprecated as a duplicate of the VT 'F5 BIG-IP - Expat XML library vulnerability
  CVE-2016-5300' (OID: 1.3.6.1.4.1.25623.1.0.140638).");

  script_tag(name:"insight", value:"The XML parser in Expat does not use sufficient entropy for hash
  initialization, which allows context-dependent attackers to cause a denial of service (CPU
  consumption) via crafted identifiers in an XML document.");

  script_tag(name:"impact", value:"An attacker may be able to cause a denial-of-service (DoS) attack
  via crafted identifiers in an XML document.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K70938105");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);