# Copyright (C) 2021 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1625.1");
  script_cve_id("CVE-2011-3102", "CVE-2011-3919", "CVE-2012-0841", "CVE-2012-2807", "CVE-2012-5134", "CVE-2013-0338", "CVE-2013-0339", "CVE-2013-2877");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-07 19:05:00 +0000 (Thu, 07 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1625-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1625-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131625-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2013:1625-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a LTSS rollup update for the libxml2 library that fixes various security issues.

 *

 CVE-2013-2877: parser.c in libxml2 allowed remote attackers to cause a denial of service (out-of-bounds read)
via a document that ends abruptly, related to the lack of certain checks for the XML_PARSER_EOF state.

 *

 CVE-2013-0338: libxml2 allowed context-dependent attackers to cause a denial of service (CPU and memory consumption) via an XML file containing an entity declaration with long replacement text and many references to this entity, aka 'internal entity expansion' with linear complexity.

 *

 CVE-2012-5134: Heap-based buffer underflow in the xmlParseAttValueComplex function in parser.c in libxml2 allowed remote attackers to cause a denial of service or possibly execute arbitrary code via crafted entities in an XML document.

 *

 CVE-2012-2807: Multiple integer overflows in libxml2 on 64-bit Linux platforms allowed remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors.

 *

 CVE-2011-3102: Off-by-one error in libxml2 allowed remote attackers to cause a denial of service
(out-of-bounds write) or possibly have unspecified other impact via unknown vectors.

 *

 CVE-2012-0841: libxml2 computed hash values without restricting the ability to trigger hash collisions predictably, which allows context-dependent attackers to cause a denial of service (CPU consumption) via crafted XML data.

 *

 CVE-2011-3919: A heap-based buffer overflow during decoding of entity references with overly long names has been fixed.

Security Issue references:

 * CVE-2013-0338
>
 * CVE-2013-0339
>
 * CVE-2012-5134
>
 * CVE-2012-2807
>
 * CVE-2011-3102
>
 * CVE-2012-0841
>
 * CVE-2011-3919
>
 * CVE-2013-2877
>");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Server 10 SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.23~15.39.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.23~15.39.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.23~15.39.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-32bit", rpm:"libxml2-32bit~2.6.23~15.39.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.6.23~15.39.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
