import {_ as Ee} from "./MobileHeader.vue_vue_type_script_setup_true_lang-lGJHWXUr.js";
import {_ as Re} from "./PcHeader.vue_vue_type_script_setup_true_lang-BY3JEAN_.js";
import {k as G, C as W, u as he, l as Fe, b as Ue} from "./su-C6U772VT.js";
import {s as Z, E as Ke, T as xe, R as Be, e as Ce, f as fe, F as me, i as Ae, u as $e, V as De, d as Ne, A as Ve} from "./update-store-BP3PGMSQ.js";
import {g as Me, c as Oe, b as qe, d as Qe, e as Ge} from "./index.model-CrIPcSmh.js";
import {b as de, D as He} from "./index-CsRkz4iz.js";
import {i as ie} from "./types-DrJxM22u.js";
import {b8 as H, t as o, r as L, e as le, d as z, z as Y, X as g, j, al as N, s as u, c as i, k as M, aB as _e, ai as Q, a7 as E, b as se, y as re, f as ue, g as x, O as Xe, J as Se, F as Ie, i as ve, aw as je, D as ne, G as ze, H as Je, aU as We, a as Ye, aa as Ze, b6 as en, b7 as nn} from "./vendor-vmc0LyWq.js";
import {p as on, g as tn} from "./InitLogin.model-CElpcWFF.js";
import {c as an, Q as Le} from "./index-CdG7PABK.js";
import {u as ke} from "./useInternet-DX4_GK1o.js";
import {u as sn, a as ln} from "./quickSetupStep-3Z0BNmz4.js";
import {u as rn} from "./firmware-cILFJJ2_.js";
import {u as J} from "./useLoading-CKsAfQGF.js";
import {_ as oe} from "./_plugin-vue_export-helper-DlAUqK2U.js";
import {A as un} from "./accountValidate-DxpaaPV8.js";
import {l as cn, c as dn, a as pn, b as fn, _ as mn, C as _n, d as vn, e as gn} from "./CloudServer.vue_vue_type_script_setup_true_lang-DYsEU0Fw.js";
import {u as wn} from "./useLanguage-D0AaRkm5.js";
import "./index-JfE_dcoz.js";
import "./index-C9zvdopb.js";
import "./tpLinkCloud-BT3Twas3.js";
import "./domain-B7RX4Eps.js";
import "./useSingleSave-FN0PjKAu.js";
function yn(e) {
    const n = {
        password: e,
        operation: "login",
        confirm: !0
    };
    return Z.write("/login?form=initial_login", n, {
        preventSuccess: !0,
        preventError: !0,
        withAesKey: !0
    })
}
var k = (e => (e.Init = "InitLogin",
e.Local = "LocalLogin",
e.Cloud = "CloudLogin",
e))(k || {})
  , pe = (e => (e[e.Custom = 0] = "Custom",
e[e.Suggestion = 1] = "Suggestion",
e))(pe || {});
function bn() {
    const e = H()
      , n = o(e, "t")
      , s = L()
      , t = le({
        password: "",
        confirmPassword: ""
    })
      , a = {
        password: on,
        confirmPassword: {
            required: !0,
            message: n.value("error.00000062")
        }
    };
    return {
        formRef: s,
        form: t,
        rules: a
    }
}
const Te = z({
    __name: "InitPwdForm",
    props: {
        disabled: Y.bool.def(!1),
        saveText: Y.string.def("")
    },
    emits: ["save"],
    setup(e, {expose: n, emit: s}) {
        const t = H()
          , a = o(t, "t")
          , p = bn()
          , d = o(p, "form")
          , f = o(p, "formRef")
          , v = o(p, "rules");
        async function l() {
            var m;
            await ((m = f.value) == null ? void 0 : m.validate( () => d.value.confirmPassword !== d.value.password ? {
                confirmPassword: a.value("error.00000080")
            } : !0)),
            s("save", d.value.password)
        }
        function c(m) {
            var r;
            (r = f.value) == null || r.setError("password", m)
        }
        return n({
            setError: c
        }),
        (m, r) => {
            const _ = g("su-password")
              , b = g("su-form-item")
              , $ = g("su-button")
              , F = g("su-form-content-item")
              , R = g("su-form");
            return N(),
            j(R, {
                ref_key: "formRef",
                ref: f,
                model: d.value,
                rules: v.value,
                disabled: e.disabled
            }, {
                default: u( () => [i(b, {
                    label: m.$t("login.newPassword"),
                    name: "password"
                }, {
                    default: u( () => [i(_, {
                        value: d.value.password,
                        "onUpdate:value": r[0] || (r[0] = h => d.value.password = h),
                        "show-requirement": "",
                        requirements: M(tn)(),
                        "data-cy": "newPasswordInput"
                    }, null, 8, ["value", "requirements"])]),
                    _: 1
                }, 8, ["label"]), i(b, {
                    label: m.$t("login.confirmPassword"),
                    name: "confirmPassword"
                }, {
                    default: u( () => [i(_, {
                        value: d.value.confirmPassword,
                        "onUpdate:value": r[1] || (r[1] = h => d.value.confirmPassword = h),
                        "data-cy": "confirmPasswordInput",
                        onKeyup: _e(l, ["enter"])
                    }, null, 8, ["value", "onKeyup"])]),
                    _: 1
                }, 8, ["label"]), i(F, null, {
                    default: u( () => [i($, {
                        type: "primary",
                        class: "w-full my-[24px]",
                        loading: e.disabled,
                        "data-cy": "saveBtn",
                        onClick: l
                    }, {
                        default: u( () => [Q(E(e.saveText), 1)]),
                        _: 1
                    }, 8, ["loading"])]),
                    _: 1
                })]),
                _: 1
            }, 8, ["model", "rules", "disabled"])
        }
    }
})
  , te = Symbol("rsaPublicKey");
function ge(e) {
    const n = e || function() {
        let s = "12345";
        const t = (top == null ? void 0 : top.location.href) ?? ""
          , a = t.indexOf("stok=");
        return a > -1 && (s = t == null ? void 0 : t.substring(a + 5)),
        s
    }();
    xe.setToken(n)
}
async function we(e, n) {
    const t = e === k.Cloud ? n : hn(n)
      , a = await Me();
    Ke.init(t, a.seq, ...a.key)
}
function ce(e, n) {
    return Be.encrypt(e, ...n)
}
function hn(e) {
    const n = `admin${e}`;
    return fe.isSupport(me.SHA256) ? Ce.SHA256(n).toString() : Ce.MD5(n).toString()
}
const X = Ae.global.t
  , Cn = 2;
function Ln(e, n) {
    const s = e + n;
    let t = "";
    fe.isSupport(me.LOGIN_FAILED) ? t = X("login.incorrectPassword", {
        times: e,
        maxTimes: s,
        hour: Cn
    }) : n === 0 ? t = X("error.00000089", {
        attemptTimes: s
    }) : e >= n ? t = X("login.loginRemainTimes", {
        failedTimes: e,
        remainTimes: n
    }) : t = X("login.loginFailed"),
    G.confirm({
        content: t
    })
}
function $n(e, n) {
    G.confirm({
        content: X("error.00000089", {
            attemptTimes: e + n
        })
    })
}
function Sn(e) {
    G.confirm({
        content: X("login.userConflict"),
        onOk: e
    })
}
function In() {
    const e = fe.isSupport(me.MULTIPLE_LOGIN) ? X("login.multipleLogin") : X("login.loginFailed");
    G.info({
        content: e
    })
}
const ae = {
    USER_CONFLICT: "user conflict",
    LOGIN_FAILED: "login failed",
    MAX_ATTEMPT: "exceeded max attempts",
    MULTIPLE_LOGIN: "multiple login"
};
function ye(e, n) {
    const s = e === k.Init
      , t = s ? 5 : 7
      , a = n.onError
      , p = n.onConfirm
      , {t: d, te: f} = H();
    function v(l) {
        var $, F, R;
        const c = l.errorCode ?? ""
          , m = (($ = l.data) == null ? void 0 : $.errorcode) ?? ""
          , r = ((F = l.data) == null ? void 0 : F.failureCount) ?? 0
          , _ = ((R = l.data) == null ? void 0 : R.attemptsAllowed) ?? 0
          , b = r <= t;
        if (m && b) {
            const h = String(m).replace(/^-/, "E");
            if (f(`error.${h}`))
                return a(d(`error.${h}`))
        } else if (!s && c)
            switch (c) {
            case ae.USER_CONFLICT:
                return Sn(p);
            case ae.LOGIN_FAILED:
                return Ln(r, _);
            case ae.MAX_ATTEMPT:
                return $n(r, _);
            case ae.MULTIPLE_LOGIN:
                return In()
            }
        W.error(d("common.operationFailed"))
    }
    return {
        handleError: v
    }
}
function be() {
    const e = $e()
      , n = o(e, "deviceConfig")
      , s = ke()
      , t = o(s, "checkInternet")
      , a = o(s, "isConnected")
      , p = sn()
      , d = o(p, "setUnFinishedStep")
      , f = rn()
      , v = o(f, "init")
      , l = o(f, "isFactoryDefault")
      , c = o(f, "isUpgradedInQs")
      , m = o(f, "setIsUpgradedInQs")
      , r = ln()
      , _ = o(r, "cloudBindFlag")
      , b = o(r, "setCloudBind")
      , $ = se( () => c.value && (a.value && !_.value || n.value.supportUXPlan));
    async function F() {
        await v.value(),
        c.value && await R(),
        l.value ? de.push({
            name: "quickSetup"
        }) : $.value ? (await m.value(!1),
        h(),
        de.push({
            name: "quickSetup"
        })) : de.push({
            path: "/"
        })
    }
    async function R() {
        if (await t.value(),
        a.value) {
            const {isbind: B} = await an();
            b.value(B)
        }
    }
    function h() {
        const B = a.value && !_.value;
        d.value(B ? Le.CloudLogin : Le.UXPlan)
    }
    return {
        goToDefault: F
    }
}
const kn = {
    class: "login-content"
}
  , Tn = {
    class: "login-title max-md:hidden"
}
  , Pn = {
    class: "login-description max-md:hidden"
}
  , En = z({
    __name: "InitLogin",
    setup(e) {
        const {t: n} = H()
          , s = L()
          , t = be()
          , a = o(t, "goToDefault")
          , p = J(m)
          , d = o(p, "loading")
          , f = o(p, "event")
          , v = ye(k.Init, {
            onError: r => {
                var _;
                (_ = s.value) == null || _.setError(r)
            }
        })
          , l = o(v, "handleError")
          , c = re(te, L(["", ""]));
        async function m(r) {
            try {
                await we(k.Init, r);
                const _ = ce(r, c.value)
                  , b = await yn(_);
                ge(b.stok),
                await a.value()
            } catch (_) {
                ie(_) ? l.value(_) : W.error(n("common.operationFailed"))
            }
        }
        return (r, _) => (N(),
        ue("div", kn, [x("div", Tn, E(M(n)("login.initLogin")), 1), x("div", Pn, E(M(n)("login.initLoginNote")), 1), i(Te, {
            class: "pt-[40px] max-md:pt-0",
            "label-width": {
                span: 10
            },
            "content-width": {
                span: 10
            },
            disabled: d.value,
            "save-text": r.$t("login.letsGetStarted"),
            onSave: f.value
        }, null, 8, ["disabled", "save-text", "onSave"])]))
    }
})
  , Rn = oe(En, [["__scopeId", "data-v-3440e5c0"]]);
function Fn(e, n) {
    const s = {
        password: e,
        operation: "login",
        confirm: n
    };
    return Z.write("/login?form=login", s, {
        preventSuccess: !0,
        preventError: !0,
        withAesKey: !0
    })
}
function Un() {
    return Z.read("/login?form=vercode")
}
function Kn(e) {
    return Z.write("/login?form=vercode", {
        vercode: e.trim()
    }, {
        preventSuccess: !0
    })
}
function xn() {
    return Z.read("/login?form=password")
}
function Bn(e, n) {
    const s = {
        password: e,
        vercode: n,
        confirm: !0
    };
    return Z.write("/login?form=password", s)
}
const Pe = new un().isRequired().asciiVisible().lengthRange({
    min: 1,
    max: 32
}).rule;
async function An(e, n) {
    return await Fn(e, n)
}
function Dn() {
    let e, n = L(0);
    Xe(t);
    function s(a) {
        n.value = a,
        e = window.setInterval( () => {
            n.value -= 1,
            n.value || t()
        }
        , 1e3)
    }
    function t() {
        clearInterval(e),
        e = -1,
        n.value = 0
    }
    return {
        countdown: n,
        startCountdown: s,
        stopCountdown: t
    }
}
const Nn = z({
    __name: "ForgetPassword",
    props: {
        visible: Y.bool.isRequired
    },
    emits: ["update:visible", "confirmed"],
    setup(e, {emit: n}) {
        let t = Se(e, "visible", n);
        const a = L("")
          , p = se( () => !a.value.trim())
          , d = Dn()
          , f = o(d, "countdown")
          , v = o(d, "startCountdown")
          , l = H()
          , c = o(l, "t")
          , m = o(l, "te")
          , r = se( () => f.value ? `${f.value} ${c.value("unit.second")}` : c.value("login.send"));
        async function _() {
            try {
                await Un(),
                v.value(60)
            } catch (I) {
                if (I.errorCode === "permission denied")
                    return;
                G.info(c.value("login.forgetPwdSendFailed"))
            }
        }
        const b = J(_)
          , $ = o(b, "loading")
          , F = o(b, "event");
        async function R() {
            try {
                await Kn(a.value),
                t.value = !1,
                n("confirmed", a.value)
            } catch (I) {
                ie(I) && S(I)
            }
        }
        const h = J(R)
          , B = o(h, "loading")
          , w = o(h, "event");
        function S(I) {
            m.value(`error.${I.errorCode}`) && G.info({
                content: c.value(`error.${I.errorCode}`)
            })
        }
        return (I, O) => {
            const ee = g("su-input")
              , T = g("su-form-item")
              , C = g("su-button")
              , y = g("su-form-content-item")
              , P = g("su-form")
              , A = g("su-tip")
              , V = g("su-dialog");
            return N(),
            j(V, {
                visible: t.value,
                "onUpdate:visible": O[1] || (O[1] = U => t.value = U),
                top: 300,
                title: I.$t("login.forgetPassword")
            }, {
                default: u( () => [x("span", null, E(I.$t("login.localPwdInfo")), 1), i(P, {
                    class: "py-[24px]"
                }, {
                    default: u( () => [i(T, {
                        label: I.$t("login.verificationCode")
                    }, {
                        default: u( () => [i(ee, {
                            value: a.value,
                            "onUpdate:value": O[0] || (O[0] = U => a.value = U),
                            "data-cy": "verCodeInput"
                        }, null, 8, ["value"])]),
                        _: 1
                    }, 8, ["label"]), i(y, null, {
                        default: u( () => [i(C, {
                            type: "primary",
                            class: "w-full",
                            disabled: !!f.value,
                            loading: $.value,
                            "data-cy": "sendCodeBtn",
                            onClick: F.value
                        }, {
                            default: u( () => [Q(E(r.value), 1)]),
                            _: 1
                        }, 8, ["disabled", "loading", "onClick"])]),
                        _: 1
                    }), i(y, null, {
                        default: u( () => [i(C, {
                            type: "primary",
                            class: "w-full",
                            disabled: p.value,
                            loading: B.value,
                            "data-cy": "confirmBtn",
                            onClick: w.value
                        }, {
                            default: u( () => [Q(E(I.$t("login.confirm")), 1)]),
                            _: 1
                        }, 8, ["disabled", "loading", "onClick"])]),
                        _: 1
                    })]),
                    _: 1
                }), i(A, null, {
                    default: u( () => [Q(E(I.$t("login.localPwdNote")), 1)]),
                    _: 1
                })]),
                _: 1
            }, 8, ["visible", "title"])
        }
    }
})
  , Vn = z({
    __name: "ResetPassword",
    props: {
        visible: Y.bool.def(!1),
        verificationCode: Y.string.isRequired
    },
    setup(e) {
        const n = e;
        let s = Se(n, "visible");
        const t = re(te, L(["", ""]))
          , a = J(f)
          , p = o(a, "loading")
          , d = o(a, "event");
        async function f(v) {
            const l = ce(v, t.value);
            await Bn(l, n.verificationCode),
            s.value = !1
        }
        return (v, l) => {
            const c = g("su-tip")
              , m = g("su-dialog");
            return N(),
            j(m, {
                visible: s.value,
                "onUpdate:visible": l[0] || (l[0] = r => s.value = r),
                top: 300,
                title: v.$t("login.resetPwd")
            }, {
                default: u( () => [i(c, {
                    type: "secondary"
                }, {
                    default: u( () => [Q(E(v.$t("login.resetPwdNote")), 1)]),
                    _: 1
                }), i(Te, {
                    class: "mt-[24px]",
                    disabled: p.value,
                    "save-text": v.$t("common.saveUpper"),
                    onSave: d.value
                }, null, 8, ["disabled", "save-text", "onSave"])]),
                _: 1
            }, 8, ["visible", "title"])
        }
    }
});
async function Mn() {
    try {
        const e = await xn();
        return !!(e != null && e.enable_rec)
    } catch {
        return !1
    }
}
function On() {
    let e = L(!1);
    const n = H()
      , s = o(n, "t")
      , t = J(d)
      , a = o(t, "loading")
      , p = o(t, "event");
    async function d() {
        await Mn() ? e.value = !0 : G.info({
            title: s.value("login.forgetPassword"),
            content: s.value("login.restoreNote")
        })
    }
    return {
        visible: e,
        loading: a,
        handleForget: p
    }
}
const qn = {
    class: "login-content"
}
  , Qn = {
    class: "login-title max-md:hidden"
}
  , Gn = {
    class: "w-[100%] text-right"
}
  , Hn = z({
    __name: "LocalLogin",
    setup(e) {
        const n = H()
          , s = o(n, "t")
          , t = ee()
          , a = o(t, "formRef")
          , p = o(t, "form")
          , d = o(t, "rules");
        let f = L("")
          , v = L(!1)
          , l = L(!1);
        const c = L(-1)
          , m = be()
          , r = o(m, "goToDefault")
          , _ = J(I)
          , b = o(_, "loading")
          , $ = o(_, "event")
          , F = ye(k.Local, {
            onError: T => {
                var C;
                (C = a.value) == null || C.setError("password", T)
            }
            ,
            onConfirm: () => {
                l.value = !0,
                $.value()
            }
        })
          , R = o(F, "handleError")
          , {visible: h, loading: B, handleForget: w} = On()
          , S = re(te, L(["", ""]));
        async function I() {
            var T;
            if (!(c.value > -1)) {
                await ((T = a.value) == null ? void 0 : T.validate());
                try {
                    await we(k.Local, p.value.password);
                    const C = ce(p.value.password, S.value)
                      , y = await An(C, l.value || void 0);
                    ge(y.stok),
                    await r.value()
                } catch (C) {
                    l.value = !1,
                    ie(C) ? R.value(C) : W.error(s.value("common.operationFailed"))
                }
            }
        }
        function O(T) {
            f.value = T,
            v.value = !0
        }
        function ee() {
            const T = L()
              , C = le({
                password: ""
            });
            return {
                formRef: T,
                form: C,
                rules: {
                    password: Pe
                }
            }
        }
        return (T, C) => {
            const y = g("su-password")
              , P = g("su-form-item")
              , A = g("su-form")
              , V = g("su-button")
              , U = g("su-flat-button");
            return N(),
            ue(Ie, null, [x("div", qn, [x("div", Qn, E(T.$t("login.localLogin")), 1), i(A, {
                ref_key: "formRef",
                ref: a,
                model: p.value,
                rules: d.value,
                "label-width": {
                    span: 10
                },
                "content-width": {
                    span: 10
                },
                class: "pt-[48px] max-md:pt-0"
            }, {
                default: u( () => [i(P, {
                    label: T.$t("login.localPassword"),
                    name: "password"
                }, {
                    default: u( () => [i(y, {
                        value: p.value.password,
                        "onUpdate:value": C[0] || (C[0] = K => p.value.password = K),
                        disabled: b.value,
                        "data-cy": "localPassword",
                        onKeyup: _e($.value, ["enter"])
                    }, null, 8, ["value", "disabled", "onKeyup"])]),
                    _: 1
                }, 8, ["label"])]),
                _: 1
            }, 8, ["model", "rules"]), i(V, {
                type: "primary",
                class: "login-btn",
                loading: b.value,
                "data-cy": "loginBtn",
                onClick: $.value
            }, {
                default: u( () => [Q(E(T.$t("login.loginButtonText")), 1)]),
                _: 1
            }, 8, ["loading", "onClick"]), x("div", Gn, [i(U, {
                loading: M(B),
                class: "align-right",
                "data-cy": "forgetPasswordBtn",
                onClick: M(w)
            }, {
                default: u( () => [Q(E(T.$t("login.forgetPassword")), 1)]),
                _: 1
            }, 8, ["loading", "onClick"])])]), M(h) ? (N(),
            j(Nn, {
                key: 0,
                visible: M(h),
                "onUpdate:visible": C[1] || (C[1] = K => je(h) ? h.value = K : null),
                "data-cy": "forgetPasswordMsg",
                onConfirmed: O
            }, null, 8, ["visible"])) : ve("", !0), i(Vn, {
                visible: v.value,
                "onUpdate:visible": C[2] || (C[2] = K => v.value = K),
                "verification-code": f.value
            }, null, 8, ["visible", "verification-code"])], 64)
        }
    }
})
  , Xn = oe(Hn, [["__scopeId", "data-v-9c5198fb"]])
  , jn = {
    class: "login-content"
}
  , zn = {
    class: "login-description"
}
  , Jn = {
    class: "w-full"
}
  , Wn = z({
    __name: "CloudBind",
    props: {
        loading: Y.bool.def(!1)
    },
    emits: ["bind"],
    setup(e, {emit: n}) {
        const s = v()
          , t = o(s, "formRef")
          , a = o(s, "form")
          , p = o(s, "rules")
          , d = re(te, L(["", ""]));
        async function f() {
            var c;
            await ((c = t.value) == null ? void 0 : c.validate());
            const l = ce(a.value.password, d.value);
            n("bind", l)
        }
        function v() {
            const l = L()
              , c = le({
                password: ""
            });
            return {
                formRef: l,
                form: c,
                rules: {
                    password: Pe
                }
            }
        }
        return (l, c) => {
            const m = g("su-password")
              , r = g("su-form-item")
              , _ = g("su-button")
              , b = g("su-form");
            return N(),
            ue("div", jn, [x("div", zn, E(l.$t("login.bindAccount")), 1), i(b, {
                ref_key: "formRef",
                ref: t,
                model: a.value,
                rules: p.value,
                "label-width": "100%",
                "content-width": "100%",
                class: "pt-[48px]"
            }, {
                default: u( () => [i(r, {
                    label: l.$t("login.localPassword"),
                    disabled: e.loading,
                    name: "password"
                }, {
                    default: u( () => [i(m, {
                        value: a.value.password,
                        "onUpdate:value": c[0] || (c[0] = $ => a.value.password = $),
                        "data-cy": "cloudPassword",
                        onKeyup: _e(f, ["enter"])
                    }, null, 8, ["value", "onKeyup"])]),
                    _: 1
                }, 8, ["label", "disabled"]), i(r, {
                    "empty-label": ""
                }, {
                    default: u( () => [x("div", Jn, [i(_, {
                        type: "primary",
                        class: "login-btn",
                        loading: e.loading,
                        "data-cy": "bindBtn",
                        onClick: f
                    }, {
                        default: u( () => [Q(E(l.$t("operation.bindUpper")), 1)]),
                        _: 1
                    }, 8, ["loading"])])]),
                    _: 1
                })]),
                _: 1
            }, 8, ["model", "rules"])])
        }
    }
})
  , Yn = oe(Wn, [["__scopeId", "data-v-8195869f"]])
  , Zn = z({
    __name: "CloudLogin",
    setup(e) {
        let n = L(!0);
        function s(w=!1) {
            n.value = w
        }
        let t = L(!1)
          , a = L("");
        const p = le({
            token: "",
            operation: ""
        })
          , d = H()
          , f = o(d, "t")
          , v = be()
          , l = o(v, "goToDefault")
          , c = ye(k.Cloud, {
            onError: w => {
                W.error(w)
            }
            ,
            onConfirm: () => {
                b()
            }
        })
          , m = o(c, "handleError");
        async function r(w, S) {
            if (We(p, w),
            a.value = S ?? "",
            w.operation === _n.Login)
                return _(w);
            t.value = !0
        }
        async function _(w) {
            try {
                await we(k.Cloud, w.token);
                const S = await vn(w);
                return ge(S.stok),
                S
            } catch (S) {
                return ie(S) ? m.value(S) : W.error(f.value("common.operationFailed")),
                Promise.reject(S)
            }
        }
        async function b() {
            const w = {
                ...p,
                confirm: !0
            };
            await $(w)
        }
        async function $(w) {
            const S = await _(w);
            Ne.setUserInfo({
                username: a.value,
                token: w.token,
                role: S.role ?? gn.Unknown
            }),
            l.value()
        }
        async function F(w) {
            const S = {
                ...p,
                password: w
            };
            await $(S)
        }
        const R = J(F)
          , h = o(R, "loading")
          , B = o(R, "event");
        return ne(cn, s),
        ne(dn, De.Login),
        ne(pn, r),
        ne(fn, l.value),
        (w, S) => {
            const I = g("su-scrollbar")
              , O = g("su-spin");
            return N(),
            j(O, {
                spinning: n.value,
                class: "h-[100%]"
            }, {
                default: u( () => [ze(i(I, {
                    class: "cloud-login-container"
                }, {
                    default: u( () => [i(mn, {
                        "data-cy": "tpLinkLoginForm"
                    })]),
                    _: 1
                }, 512), [[Je, !n.value && !t.value]]), !n.value && t.value ? (N(),
                j(Yn, {
                    key: 0,
                    loading: h.value,
                    onBind: B.value
                }, null, 8, ["loading", "onBind"])) : ve("", !0)]),
                _: 1
            }, 8, ["spinning"])
        }
    }
})
  , eo = oe(Zn, [["__scopeId", "data-v-7b540608"]])
  , no = e => (en("data-v-03b2fbbc"),
e = e(),
nn(),
e)
  , oo = no( () => x("div", {
    class: "login-bg"
}, null, -1))
  , to = {
    class: "login-wrapper"
}
  , ao = {
    class: "login-inner"
}
  , so = z({
    __name: "index",
    setup(e) {
        const {t: n} = H()
          , s = $e()
          , t = o(s, "setting")
          , a = wn()
          , p = o(a, "init")
          , d = o(a, "availableLanguages")
          , f = o(a, "languageLabel")
          , v = o(a, "currentLanguage")
          , l = o(a, "handleChange")
          , c = T()
          , m = o(c, "loginType")
          , r = o(c, "initLoginType")
          , _ = o(c, "changeLoginType")
          , b = C()
          , $ = o(b, "encryptKey")
          , F = o(b, "getEncryptKey");
        ne(te, $);
        const R = {
            InitLogin: Rn,
            LocalLogin: Xn,
            CloudLogin: eo
        }
          , h = L(!0)
          , B = se( () => {
            if (!h.value)
                return "";
            switch (m.value) {
            case k.Local:
                return n("login.tpLinkId");
            case k.Cloud:
                return n("login.localPassword");
            default:
                return ""
            }
        }
        );
        async function w() {
            const {mode: y} = await qe();
            h.value = He.supportCloud(y)
        }
        Ye(async () => {
            O(),
            await Promise.all([r.value(), p.value(), F.value(), w()]),
            ee()
        }
        );
        const S = [k.Local, k.Cloud];
        async function I() {
            await _.value(S[+(m.value === k.Local)]) || W.error(n("login.localSwitchToTpNoInternetTips"))
        }
        function O() {
            Ve.reset(),
            sessionStorage.removeItem("cloudMsgToken")
        }
        async function ee() {
            const y = await Oe()
              , {redirect: P, conflict: A, mode: V} = y;
            if (P && (location.href = P),
            !A)
                return;
            const {new_addr: U, dst_addr: K, dst_webpath: q} = y;
            V === pe.Custom ? G.info({
                content: n("init.conflictInfo", {
                    new_addr: U
                }),
                okText: n("networkInternet.continue")
            }) : V === pe.Suggestion && G.confirm({
                content: `${n("init.conflictInfo", {
                    new_addr: U
                })} ${n("init.conflictConfirm", {
                    dst_addr: K
                })}`,
                okText: U,
                cancelText: K,
                onCancel() {
                    const D = `//${K}${q}`;
                    location.href = D
                }
            })
        }
        function T() {
            let y = L("");
            const P = ke()
              , A = o(P, "isConnected")
              , V = o(P, "checkInternet");
            async function U() {
                const {is_default: q, cloud_ever_login: D} = await Qe();
                q ? y.value = k.Init : D ? y.value = k.Cloud : y.value = k.Local
            }
            async function K(q) {
                let D = !1;
                return q !== k.Cloud ? (y.value = q,
                D = !0,
                D) : (await V.value(),
                A.value && (y.value = q,
                D = !0),
                D)
            }
            return {
                loginType: y,
                initLoginType: U,
                changeLoginType: K
            }
        }
        function C() {
            let y = L(["", ""]);
            async function P() {
                const A = await Ge();
                y.value = A.password
            }
            return {
                encryptKey: y,
                getEncryptKey: P
            }
        }
        return (y, P) => {
            const A = g("su-space")
              , V = g("su-dropdown")
              , U = Re
              , K = Ee
              , q = g("su-flat-button");
            return N(),
            ue(Ie, null, [oo, x("div", to, [i(U, {
                class: "login-header",
                "product-name": t.value.productModel
            }, {
                rightNav: u( () => [i(V, {
                    value: v.value,
                    "onUpdate:value": P[0] || (P[0] = D => v.value = D),
                    options: d.value,
                    "data-cy": "pcCurrentLanguageSelect",
                    onChange: l.value
                }, {
                    default: u( () => [i(A, {
                        class: "cursor-pointer"
                    }, {
                        default: u( () => [i(M(he)), x("div", null, E(f.value), 1)]),
                        _: 1
                    })]),
                    _: 1
                }, 8, ["value", "options", "onChange"])]),
                _: 1
            }, 8, ["product-name"]), i(K, {
                class: "login-header mobile mobile-nav__header text-white"
            }, {
                right: u( () => [i(V, {
                    value: v.value,
                    "onUpdate:value": P[1] || (P[1] = D => v.value = D),
                    options: d.value,
                    "data-cy": "mobileCurrentLanguageSelect",
                    class: "login-dropdown",
                    onChange: l.value
                }, {
                    default: u( () => [i(A, {
                        class: "cursor-pointer"
                    }, {
                        default: u( () => [i(M(he)), x("div", null, E(f.value), 1)]),
                        _: 1
                    })]),
                    _: 1
                }, 8, ["value", "options", "onChange"])]),
                default: u( () => [i(M(Fe), {
                    class: "webui-icons",
                    width: "96"
                })]),
                _: 1
            }), x("div", ao, [(N(),
            j(Ze(R[m.value]))), B.value ? (N(),
            j(q, {
                key: 0,
                class: "btn-switch",
                "data-cy": "loginTypeSwitch",
                onClick: I
            }, {
                icon: u( () => [i(M(Ue))]),
                default: u( () => [Q(" " + E(B.value), 1)]),
                _: 1
            })) : ve("", !0)])])], 64)
        }
    }
})
  , Eo = oe(so, [["__scopeId", "data-v-03b2fbbc"]]);
export {Eo as default};
