###############################################################################
# OpenVAS Vulnerability Test
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (C) 2016 Eero Volotinen, http://www.solinor.com
#
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131285");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"creation_date", value:"2016-05-09 14:17:48 +0300 (Mon, 09 May 2016)");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_name("Mageia Linux Local Check: mgasa-2016-0169");
  script_tag(name:"insight", value:"An overflow can occur in the EVP_EncodeUpdate() function which is used for Base64 encoding of binary data. If an attacker is able to supply very large amounts of input data then a length check can overflow resulting in a heap corruption (CVE-2016-2105). An overflow can occur in the EVP_EncryptUpdate() function. If an attacker is able to supply very large amounts of input data after a previous call to EVP_EncryptUpdate() with a partial block then a length check can overflow resulting in a heap corruption (CVE-2016-2106). A MITM attacker can use a padding oracle attack to decrypt traffic when the connection uses an AES CBC cipher and the server support AES-NI (CVE-2016-2107). When ASN.1 data is read from a BIO using functions such as d2i_CMS_bio() a short invalid encoding can casuse allocation of large amounts of memory potentially consuming excessive resources or exhausting memory (CVE-2016-2109)");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0169.html");
  script_cve_id("CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2109");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2016-0169");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.2h~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
