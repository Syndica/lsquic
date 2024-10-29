const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lsquic = b.addStaticLibrary(.{
        .name = "lsquic",
        .target = target,
        .optimize = optimize,
    });
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
    });

    lsquic.addIncludePath(b.path("include"));
    lsquic.addIncludePath(b.path("src/lshpack"));
    lsquic.addIncludePath(b.path("src/liblsquic"));
    lsquic.addIncludePath(b.path("src/liblsquic/ls-qpack/"));
    lsquic.addIncludePath(boringssl.path("vendor/include"));
    lsquic.linkLibrary(boringssl.artifact("ssl"));
    lsquic.linkLibrary(boringssl.artifact("crypto"));

    const zlib_dep = b.dependency("zlib", .{
        .target = target,
        .optimize = optimize,
    });
    lsquic.linkLibrary(zlib_dep.artifact("z"));

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
    });

    lsquic.addCSourceFile(.{ .file = b.path("src/lshpack/lshpack.c") });

    const sol_client = b.addExecutable(.{
        .name = "sol_client",
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(sol_client);
    sol_client.linkLibrary(lsquic);

    // quick hack to include libevent from homebrew
    if (b.graph.host.result.os.tag == .macos) {
        sol_client.addLibraryPath(b.path("generated/event2"));
        sol_client.addIncludePath(b.path("generated"));
    }
    sol_client.linkSystemLibrary("event");
    sol_client.addIncludePath(b.path("include"));
    sol_client.addIncludePath(b.path("bin"));
    sol_client.addIncludePath(boringssl.path("vendor/include"));

    const test_config = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("bin/test_config.h.in") },
    }, .{
        .HAVE_SENDMMSG = 0,
    });
    sol_client.addConfigHeader(test_config);

    sol_client.addCSourceFiles(.{
        .root = b.path("bin"),
        .files = &.{
            "sol_client.c",
            "prog.c",
            "test_common.c",
            "test_cert.c",
            "../generated/lsquic_versions_to_string.c",
        },
    });

    const echo_server = b.addExecutable(.{
        .name = "echo_server",
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(echo_server);
    echo_server.linkLibrary(lsquic);

    // quick hack to include libevent from homebrew
    if (b.graph.host.result.os.tag == .macos) {
        echo_server.addLibraryPath(b.path("generated/event2"));
        echo_server.addIncludePath(b.path("generated"));
    }
    echo_server.linkSystemLibrary("event");
    echo_server.addIncludePath(b.path("include"));
    echo_server.addIncludePath(b.path("bin"));
    echo_server.addIncludePath(boringssl.path("vendor/include"));
    echo_server.addConfigHeader(test_config);

    echo_server.addCSourceFiles(.{
        .root = b.path("bin"),
        .files = &.{
            "echo_server.c",
            "prog.c",
            "test_common.c",
            "test_cert.c",
            "../generated/lsquic_versions_to_string.c",
        },
    });

    // TODO: fix all of the UB in the library
    lsquic.root_module.sanitize_c = false;
    sol_client.root_module.sanitize_c = false;
    echo_server.root_module.sanitize_c = false;
}
