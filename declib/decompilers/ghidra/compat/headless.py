import logging
from pathlib import Path
from typing import Union, Optional, Tuple

from pyghidra.core import _analyze_program, _get_language, _get_compiler_spec
from jpype import JClass

_l = logging.getLogger(__name__)


def open_program(
    binary_path: Optional[Union[str, Path]] = None,
    project_location: Union[str, Path] = None,
    project_name: str = None,
    program_name: str = None,
    analyze=True,
    language: str = None,
    compiler: str = None,
    loader: Union[str, JClass] = None
):
    """
    Taken from Pyhidra, but updated to also return the project associated with the program:
    https://github.com/dod-cyber-crime-center/pyhidra/blob/c878e91b53498f65f2eb0255e22189a6d172917c/pyhidra/core.py#L178
    """
    from pyghidra.launcher import PyGhidraLauncher, HeadlessPyGhidraLauncher
    if binary_path is None and project_location is None:
        raise ValueError("You must provide either a binary path or a project location.")

    if not PyGhidraLauncher.has_launched():
        launcher = HeadlessPyGhidraLauncher()
        # Force the JVM into AWT-headless mode. The "headless" launcher does not
        # set this itself, so if a (possibly stale) DISPLAY is exported Ghidra's
        # JVM tries to reach an X server and dies with:
        #   java.awt.AWTError: Can't connect to X11 window server ...
        launcher.add_vmargs("-Djava.awt.headless=true")
        launcher.start()

    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI
    project, program = _setup_project(
        binary_path=binary_path,
        project_location=project_location,
        project_name=project_name,
        program_name=program_name if program_name else project_name,
        language=language,
        compiler=compiler,
        loader=loader
    )
    GhidraScriptUtil.acquireBundleHostReference()
    flat_api = FlatProgramAPI(program)
    if analyze:
        _analyze_program(flat_api, program)

    return flat_api, project, program


def _setup_project(
    binary_path: Optional[Union[str, Path]] = None,
    project_location: Union[str, Path] = None,
    project_name: str = None,
    program_name: str = None,
    language: str = None,
    compiler: str = None,
    loader: Union[str, JClass] = None
) -> Tuple["GhidraProject", "Program"]:
    from ghidra.base.project import GhidraProject
    from ghidra.util.exception import NotFoundException
    from java.lang import ClassLoader
    from java.io import IOException

    if binary_path is not None:
        binary_path = Path(binary_path)
    if project_location:
        project_location = Path(project_location)
    else:
        project_location = binary_path.parent
    if not project_name:
        project_name = f"{binary_path.name}_ghidra"
    project_location /= project_name

    # Ensure the project location directory exists
    project_location.mkdir(exist_ok=True, parents=True)

    if isinstance(loader, str):
        from java.lang import ClassNotFoundException
        try:
            gcl = ClassLoader.getSystemClassLoader()
            loader = JClass(loader, gcl)
        except (TypeError, ClassNotFoundException) as e:
            raise ValueError from e

    if isinstance(loader, JClass):
        from ghidra.app.util.opinion import Loader
        if not Loader.class_.isAssignableFrom(loader):
            raise TypeError(f"{loader} does not implement ghidra.app.util.opinion.Loader")

    # Open/Create project
    program: "Program" = None
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        # XXX: binsync patch added here:
        if binary_path is not None or program_name is not None:
            if program_name is None:
                program_name = binary_path.name
            if project.getRootFolder().getFile(program_name):
                program = project.openProgram("/", program_name, False)
    except (IOException, NotFoundException):
        project = GhidraProject.createProject(project_location, project_name, False)

    # NOTE: GhidraProject.importProgram behaves differently when a loader is provided
    # loaderClass may not be null so we must use the correct method override

    if binary_path is not None and program is None:
        if language is None:
            if loader is None:
                program = project.importProgram(binary_path)
            else:
                program = project.importProgram(binary_path, loader)
            if program is None:
                raise RuntimeError(f"Ghidra failed to import '{binary_path}'. Try providing a language manually.")
        else:
            lang = _get_language(language)
            comp = _get_compiler_spec(lang, compiler)
            if loader is None:
                program = project.importProgram(binary_path, lang, comp)
            else:
                program = project.importProgram(binary_path, loader, lang, comp)
            if program is None:
                message = f"Ghidra failed to import '{binary_path}'. "
                if compiler:
                    message += f"The provided language/compiler pair ({language} / {compiler}) may be invalid."
                else:
                    message += f"The provided language ({language}) may be invalid."
                raise ValueError(message)
        if program_name:
            program.setName(program_name)
        project.saveAs(program, "/", program.getName(), True)

    return project, program

def close_program(program, project) -> bool:
    """
    Returns true if closing was successful, false otherwise.

    """
    from ghidra.app.script import GhidraScriptUtil

    try:
        GhidraScriptUtil.releaseBundleHostReference()
        project.save(program)
        project.close()
        return True
    except Exception as e:
        _l.critical("Failed to close project: %s", e)

    return False
