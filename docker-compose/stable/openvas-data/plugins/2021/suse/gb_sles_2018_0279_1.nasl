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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0279.1");
  script_cve_id("CVE-2018-5748");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0279-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180279-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2018:0279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvirt provides several fixes.
This security issue was fixed:
- CVE-2018-5748: Prevent resource exhaustion via qemuMonitorIORead()
 method which allowed to cause DoS (bsc#1076500).
These security issues were fixed:
- Add a qemu hook script providing functionality similar to Xen's
 block-dmmd script. (fate#324177)
- schema: Make disk driver name attribute optional. (bsc#1073973)
- virt-create-rootfs: Handle all SLE 12 versions. (bsc#1072887)
- libvirt-guests: Fix the 'stop' operation when action is 'suspend'.
 (bsc#1070130)
- s390: Fix missing host cpu model info. (bsc#1065766)
- cpu: Add new EPYC CPU model. (bsc#1052825, fate#324038)
- pci: Fix the detection of the link's maximum speed. (bsc#1064947)
- nodedev: Increase the netlink socket buffer size. (bsc#1035442)
- storage: Fix a race between the volume creation and the pool refresh.
 (bsc#1062571)
- daemon: Drop the minsize directive from hypervisor logrotate files.
 (bsc#1062760)");

  script_tag(name:"affected", value:"'libvirt' package(s) on SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Desktop 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin", rpm:"libvirt-admin~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin-debuginfo", rpm:"libvirt-admin-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-debuginfo", rpm:"libvirt-client-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-debuginfo", rpm:"libvirt-daemon-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface-debuginfo", rpm:"libvirt-daemon-driver-interface-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc-debuginfo", rpm:"libvirt-daemon-driver-lxc-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network-debuginfo", rpm:"libvirt-daemon-driver-network-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev-debuginfo", rpm:"libvirt-daemon-driver-nodedev-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter-debuginfo", rpm:"libvirt-daemon-driver-nwfilter-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu-debuginfo", rpm:"libvirt-daemon-driver-qemu-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret-debuginfo", rpm:"libvirt-daemon-driver-secret-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core", rpm:"libvirt-daemon-driver-storage-core~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core-debuginfo", rpm:"libvirt-daemon-driver-storage-core-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk", rpm:"libvirt-daemon-driver-storage-disk~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk-debuginfo", rpm:"libvirt-daemon-driver-storage-disk-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi", rpm:"libvirt-daemon-driver-storage-iscsi~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi-debuginfo", rpm:"libvirt-daemon-driver-storage-iscsi-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical", rpm:"libvirt-daemon-driver-storage-logical~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical-debuginfo", rpm:"libvirt-daemon-driver-storage-logical-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath", rpm:"libvirt-daemon-driver-storage-mpath~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath-debuginfo", rpm:"libvirt-daemon-driver-storage-mpath-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi", rpm:"libvirt-daemon-driver-storage-scsi~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi-debuginfo", rpm:"libvirt-daemon-driver-storage-scsi-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-qemu", rpm:"libvirt-daemon-qemu~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-debugsource", rpm:"libvirt-debugsource~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs", rpm:"libvirt-libs~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs-debuginfo", rpm:"libvirt-libs-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock-debuginfo", rpm:"libvirt-lock-sanlock-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss", rpm:"libvirt-nss~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss-debuginfo", rpm:"libvirt-nss-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd", rpm:"libvirt-daemon-driver-storage-rbd~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd-debuginfo", rpm:"libvirt-daemon-driver-storage-rbd-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl", rpm:"libvirt-daemon-driver-libxl~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl-debuginfo", rpm:"libvirt-daemon-driver-libxl-debuginfo~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-xen", rpm:"libvirt-daemon-xen~3.3.0~5.13.1", rls:"SLES12.0SP3"))) {
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
