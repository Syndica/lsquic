const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const force_pic = b.option(
        bool,
        "force_pic",
        "Force PIC enabled when building the libraries",
    );

    const lsquic = b.addLibrary(.{
        .name = "lsquic",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            // TODO: remove this when passing optionals through `b.option` is possible.
            .pic = if (force_pic == true) true else null,
        }),
    });
    lsquic.linkLibC();
    b.installArtifact(lsquic);

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("include/lsquic.h"),
        .target = target,
        .optimize = optimize,
    });
    const mod = b.addModule("lsquic", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = translate_c.getOutput(),
    });
    mod.linkLibrary(lsquic);

    const boringssl = b.dependency("boringssl", .{
        .target = target,
        .optimize = optimize,
        .force_pic = force_pic == true,
    });
    const ssl = boringssl.artifact("ssl");
    const crypto = boringssl.artifact("crypto");

    // TODO: remove in Zig 0.14.1 (hopefully)
    ssl.bundle_ubsan_rt = true;
    crypto.bundle_ubsan_rt = true;

    lsquic.addIncludePath(b.path("include"));
    lsquic.addIncludePath(b.path("src/lshpack"));
    lsquic.addIncludePath(b.path("src/liblsquic"));
    lsquic.addIncludePath(b.path("src/liblsquic/ls-qpack/"));
    lsquic.addIncludePath(b.path("src/lshpack/deps/xxhash"));
    lsquic.addIncludePath(boringssl.path("vendor/include"));
    lsquic.linkLibrary(ssl);
    lsquic.linkLibrary(crypto);

    const zlib_dep = b.dependency("zlib", .{
        .target = target,
        .optimize = optimize,
    });
    const zlib_artifact = zlib_dep.artifact("z");
    zlib_artifact.root_module.pic = if (force_pic == true) true else null;
    lsquic.linkLibrary(zlib_artifact);

    lsquic.addCSourceFiles(.{
        .root = b.path("src/liblsquic"),
        .files = &.{
            "ls-qpack/lsqpack.c",
            "lsquic_xxhash.c",
            "ls-sfparser.c",
            "lsquic_adaptive_cc.c",
            "lsquic_alarmset.c",
            "lsquic_arr.c",
            "lsquic_attq.c",
            "lsquic_bbr.c",
            "lsquic_bw_sampler.c",
            "lsquic_cfcw.c",
            "lsquic_chsk_stream.c",
            "lsquic_conn.c",
            "lsquic_crand.c",
            "lsquic_crt_compress.c",
            "lsquic_crypto.c",
            "lsquic_cubic.c",
            "lsquic_di_error.c",
            "lsquic_di_hash.c",
            "lsquic_di_nocopy.c",
            "lsquic_enc_sess_common.c",
            "lsquic_enc_sess_ietf.c",
            "lsquic_eng_hist.c",
            "lsquic_engine.c",
            "lsquic_ev_log.c",
            "lsquic_frab_list.c",
            "lsquic_frame_common.c",
            "lsquic_frame_reader.c",
            "lsquic_frame_writer.c",
            "lsquic_full_conn.c",
            "lsquic_full_conn_ietf.c",
            "lsquic_global.c",
            "lsquic_handshake.c",
            "lsquic_hash.c",
            "lsquic_hcsi_reader.c",
            "lsquic_hcso_writer.c",
            "lsquic_headers_stream.c",
            "lsquic_hkdf.c",
            "lsquic_hpi.c",
            "lsquic_hspack_valid.c",
            "lsquic_http.c",
            "lsquic_http1x_if.c",
            "lsquic_logger.c",
            "lsquic_malo.c",
            "lsquic_min_heap.c",
            "lsquic_mini_conn.c",
            "lsquic_mini_conn_ietf.c",
            "lsquic_minmax.c",
            "lsquic_mm.c",
            "lsquic_pacer.c",
            "lsquic_packet_common.c",
            "lsquic_packet_gquic.c",
            "lsquic_packet_in.c",
            "lsquic_packet_out.c",
            "lsquic_packet_resize.c",
            "lsquic_parse_Q046.c",
            "lsquic_parse_Q050.c",
            "lsquic_parse_common.c",
            "lsquic_parse_gquic_be.c",
            "lsquic_parse_gquic_common.c",
            "lsquic_parse_ietf_v1.c",
            "lsquic_parse_iquic_common.c",
            "lsquic_pr_queue.c",
            "lsquic_purga.c",
            "lsquic_qdec_hdl.c",
            "lsquic_qenc_hdl.c",
            "lsquic_qlog.c",
            "lsquic_qpack_exp.c",
            "lsquic_rechist.c",
            "lsquic_rtt.c",
            "lsquic_send_ctl.c",
            "lsquic_senhist.c",
            "lsquic_set.c",
            "lsquic_sfcw.c",
            "lsquic_shsk_stream.c",
            "lsquic_spi.c",
            "lsquic_stock_shi.c",
            "lsquic_str.c",
            "lsquic_stream.c",
            "lsquic_tokgen.c",
            "lsquic_trans_params.c",
            "lsquic_trechist.c",
            "lsquic_util.c",
            "lsquic_varint.c",
            "lsquic_version.c",
        },
        .flags = &.{
            "-DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_DEBUG",
            "-DHAVE_BORINGSSL",
        },
    });
    lsquic.addCSourceFile(.{ .file = b.path("src/lshpack/lshpack.c") });

    // For a demo, see:
    // https://github.com/Syndica/sig/blob/11116178d7c284e9f98a249d80a9baa9b20313ed/src/net/quic_client.zig
}
