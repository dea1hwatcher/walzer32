#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <android/log.h>
#include <android/native_window.h>
#include <stdint.h>

#define LOG_TAG "Walzer32GuestGLES2"
#define LOGI(msg) __android_log_write(ANDROID_LOG_INFO, LOG_TAG, (msg))

static EGLDisplay g_display = EGL_NO_DISPLAY;
static EGLSurface g_surface = EGL_NO_SURFACE;
static EGLContext g_context = EGL_NO_CONTEXT;
static GLuint g_program = 0;
static GLint g_pos_loc = -1;
static GLint g_color_loc = -1;
static GLint g_offset_loc = -1;
static int32_t g_width = 0;
static int32_t g_height = 0;
static uint32_t g_frame_count = 0;

static const char* kVertexShader =
    "attribute vec2 aPos;\n"
    "attribute vec4 aColor;\n"
    "uniform vec2 uOffset;\n"
    "varying vec4 vColor;\n"
    "void main() {\n"
    "  vColor = aColor;\n"
    "  gl_Position = vec4(aPos + uOffset, 0.0, 1.0);\n"
    "}\n";

static const char* kFragmentShader =
    "precision mediump float;\n"
    "varying vec4 vColor;\n"
    "void main() {\n"
    "  gl_FragColor = vColor;\n"
    "}\n";

static const GLfloat kVertices[] = {
     0.0f,  0.55f,
    -0.60f, -0.45f,
     0.60f, -0.45f,
};

static const GLfloat kColors[] = {
    1.0f, 0.25f, 0.25f, 1.0f,
    0.20f, 0.95f, 0.45f, 1.0f,
    0.25f, 0.55f, 1.0f, 1.0f,
};

static GLuint compile_shader(GLenum type, const char* src) {
    GLuint shader = glCreateShader(type);
    if (!shader) {
        return 0;
    }
    glShaderSource(shader, 1, &src, 0);
    glCompileShader(shader);
    GLint compiled = 0;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (!compiled) {
        LOGI("shader compilation failed");
        glDeleteShader(shader);
        return 0;
    }
    return shader;
}

int32_t walzer32_guest_surface_created(ANativeWindow* window, int32_t width, int32_t height) {
    LOGI("walzer32_guest_surface_created entered");

    g_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (g_display == EGL_NO_DISPLAY) {
        LOGI("eglGetDisplay failed");
        return -1;
    }
    EGLint major = 0, minor = 0;
    if (!eglInitialize(g_display, &major, &minor)) {
        LOGI("eglInitialize failed");
        return -2;
    }

    const EGLint config_attribs[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_ALPHA_SIZE, 8,
        EGL_NONE
    };
    EGLConfig config = 0;
    EGLint num_configs = 0;
    if (!eglChooseConfig(g_display, config_attribs, &config, 1, &num_configs) || num_configs < 1) {
        LOGI("eglChooseConfig failed");
        return -3;
    }

    g_surface = eglCreateWindowSurface(g_display, config, (EGLNativeWindowType)window, 0);
    if (g_surface == EGL_NO_SURFACE) {
        LOGI("eglCreateWindowSurface failed");
        return -4;
    }

    const EGLint ctx_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };
    g_context = eglCreateContext(g_display, config, EGL_NO_CONTEXT, ctx_attribs);
    if (g_context == EGL_NO_CONTEXT) {
        LOGI("eglCreateContext failed");
        return -5;
    }

    if (!eglMakeCurrent(g_display, g_surface, g_surface, g_context)) {
        LOGI("eglMakeCurrent failed");
        return -6;
    }

    const char* version = (const char*)glGetString(GL_VERSION);
    const char* renderer = (const char*)glGetString(GL_RENDERER);
    if (version) {
        LOGI(version);
    }
    if (renderer) {
        LOGI(renderer);
    }

    GLuint vs = compile_shader(GL_VERTEX_SHADER, kVertexShader);
    GLuint fs = compile_shader(GL_FRAGMENT_SHADER, kFragmentShader);
    if (!vs || !fs) {
        return -7;
    }

    g_program = glCreateProgram();
    glAttachShader(g_program, vs);
    glAttachShader(g_program, fs);
    glLinkProgram(g_program);
    glDeleteShader(vs);
    glDeleteShader(fs);

    GLint linked = 0;
    glGetProgramiv(g_program, GL_LINK_STATUS, &linked);
    if (!linked) {
        LOGI("glLinkProgram failed");
        glDeleteProgram(g_program);
        g_program = 0;
        return -8;
    }

    g_pos_loc = glGetAttribLocation(g_program, "aPos");
    g_color_loc = glGetAttribLocation(g_program, "aColor");
    g_offset_loc = glGetUniformLocation(g_program, "uOffset");

    g_width = width > 0 ? width : ANativeWindow_getWidth(window);
    g_height = height > 0 ? height : ANativeWindow_getHeight(window);
    if (g_width > 0 && g_height > 0) {
        glViewport(0, 0, g_width, g_height);
    }

    LOGI("walzer32_guest_surface_created initialized GLES2 pipeline");
    return 0;
}

void walzer32_guest_surface_changed(int32_t width, int32_t height) {
    g_width = width;
    g_height = height;
    if (g_display != EGL_NO_DISPLAY && g_surface != EGL_NO_SURFACE && g_context != EGL_NO_CONTEXT) {
        eglMakeCurrent(g_display, g_surface, g_surface, g_context);
        if (width > 0 && height > 0) {
            glViewport(0, 0, width, height);
        }
    }
}

void walzer32_guest_draw_frame(void) {
    if (g_display == EGL_NO_DISPLAY || g_surface == EGL_NO_SURFACE || g_context == EGL_NO_CONTEXT || !g_program) {
        return;
    }
    eglMakeCurrent(g_display, g_surface, g_surface, g_context);
    if (g_width > 0 && g_height > 0) {
        glViewport(0, 0, g_width, g_height);
    }

    glClearColor(0.08f, 0.14f, 0.24f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    glUseProgram(g_program);

    GLfloat ox = (GLfloat)((int32_t)(g_frame_count % 60) - 30) * 0.004f;
    if (g_offset_loc >= 0) {
        glUniform2f(g_offset_loc, ox, 0.0f);
    }

    if (g_pos_loc >= 0) {
        glEnableVertexAttribArray((GLuint)g_pos_loc);
        glVertexAttribPointer((GLuint)g_pos_loc, 2, GL_FLOAT, GL_FALSE, 0, kVertices);
    }
    if (g_color_loc >= 0) {
        glEnableVertexAttribArray((GLuint)g_color_loc);
        glVertexAttribPointer((GLuint)g_color_loc, 4, GL_FLOAT, GL_FALSE, 0, kColors);
    }

    glDrawArrays(GL_TRIANGLES, 0, 3);

    if (g_pos_loc >= 0) {
        glDisableVertexAttribArray((GLuint)g_pos_loc);
    }
    if (g_color_loc >= 0) {
        glDisableVertexAttribArray((GLuint)g_color_loc);
    }

    eglSwapBuffers(g_display, g_surface);
    g_frame_count++;
    if (g_frame_count == 1 || g_frame_count == 60) {
        LOGI("walzer32_guest_draw_frame rendered frame milestone");
    }
}

void walzer32_guest_surface_destroyed(void) {
    if (g_display != EGL_NO_DISPLAY) {
        eglMakeCurrent(g_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        if (g_program) {
            glDeleteProgram(g_program);
            g_program = 0;
        }
        if (g_context != EGL_NO_CONTEXT) {
            eglDestroyContext(g_display, g_context);
            g_context = EGL_NO_CONTEXT;
        }
        if (g_surface != EGL_NO_SURFACE) {
            eglDestroySurface(g_display, g_surface);
            g_surface = EGL_NO_SURFACE;
        }
        eglTerminate(g_display);
        g_display = EGL_NO_DISPLAY;
    }
}
