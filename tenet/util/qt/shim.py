
#
# this global is used to indicate whether Qt bindings for python are present
# and available for use by Lighthouse.
#

QT_AVAILABLE = False

#------------------------------------------------------------------------------
# PyQt5 <--> PySide6/PySide2 Compatibility
#------------------------------------------------------------------------------
#
#    we use this file to shim/re-alias a few Qt API's to ensure compatibility
#    between the popular Qt frameworks. these shims serve to reduce the number
#    of compatibility checks in the plugin code that consumes them.
#
#    this file was critical for retaining compatibility with Qt4 frameworks
#    used by IDA 6.8/6.95, but it less important now. support for Qt 4 and
#    older versions of IDA will be deprecated in Lighthouse v0.9.0
#

USING_PYQT5 = False
USING_PYSIDE2 = False
USING_PYSIDE6 = False

#------------------------------------------------------------------------------
# PySide6 Compatibility (IDA 9.2+)
#------------------------------------------------------------------------------

# attempt to load PySide6 first (IDA 9.2+)
if QT_AVAILABLE == False:
    try:
        import PySide6.QtGui as QtGui
        import PySide6.QtCore as QtCore
        import PySide6.QtWidgets as QtWidgets

        # alias for less PySide6 <--> PyQt5 shimming
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

        # importing went okay, PySide6 must be available for use
        QT_AVAILABLE = True
        USING_PYSIDE6 = True

    # import failed, PySide6 is not available
    except ImportError:
        pass

#------------------------------------------------------------------------------
# PyQt5 Compatibility
#------------------------------------------------------------------------------

# attempt to load PyQt5
if QT_AVAILABLE == False:
    try:
        import PyQt5.QtGui as QtGui
        import PyQt5.QtCore as QtCore
        import PyQt5.QtWidgets as QtWidgets
        from PyQt5 import sip

        # importing went okay, PyQt5 must be available for use
        QT_AVAILABLE = True
        USING_PYQT5 = True

    # import failed, PyQt5 is not available
    except ImportError:
        pass

#------------------------------------------------------------------------------
# PySide2 Compatibility
#------------------------------------------------------------------------------

# if PyQt5 did not import, try to load PySide
if QT_AVAILABLE == False:
    try:
        import PySide2.QtGui as QtGui
        import PySide2.QtCore as QtCore
        import PySide2.QtWidgets as QtWidgets

        # alias for less PySide2 <--> PyQt5 shimming
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

        # importing went okay, PySide must be available for use
        QT_AVAILABLE = True
        USING_PYSIDE2 = True

    # import failed. No Qt / UI bindings available...
    except ImportError:
        pass

#------------------------------------------------------------------------------
# Qt6/PySide6 API Compatibility Fixes
#------------------------------------------------------------------------------

# In Qt6/PySide6, some classes were moved between modules
# QAction moved from QtWidgets to QtGui
if USING_PYSIDE6:
    if not hasattr(QtWidgets, 'QAction'):
        QtWidgets.QAction = QtGui.QAction
    
    # Patch QWheelEvent and other event classes for pos() compatibility
    # In Qt6, pos() was replaced with position() which returns QPointF
    # We add back pos() to return QPoint for compatibility
    def _add_pos_compat(event_class):
        if not hasattr(event_class, 'pos'):
            original_init = event_class.__init__
            
            def patched_init(self, *args, **kwargs):
                original_init(self, *args, **kwargs)
            
            def pos(self):
                """Qt5 compatibility: pos() returns QPoint, position() returns QPointF"""
                if hasattr(self, 'position'):
                    # Convert QPointF to QPoint
                    pos_f = self.position()
                    return QtCore.QPoint(int(pos_f.x()), int(pos_f.y()))
                return None
            
            event_class.pos = pos
    
    try:
        _add_pos_compat(QtGui.QWheelEvent)
        _add_pos_compat(QtGui.QMouseEvent)
    except:
        pass

#------------------------------------------------------------------------------
# SIP/Shiboken Compatibility
#------------------------------------------------------------------------------

# sip module for PyQt5, or shiboken6 for PySide6
sip = None

if USING_PYQT5:
    # PyQt5 already imported sip above
    pass
elif USING_PYSIDE6:
    try:
        import shiboken6

        # Create a compatibility wrapper for shiboken6
        # shiboken6 uses wrapInstance (capital I), PyQt5/sip uses wrapinstance (lowercase i)
        class Shiboken6Compat:
            """Compatibility wrapper for shiboken6 to match sip API"""

            @staticmethod
            def wrapinstance(address, qclass):
                """Convert a C++ pointer (as integer) to a PySide6 object"""
                return shiboken6.wrapInstance(address, qclass)

        sip = Shiboken6Compat()
    except ImportError:
        # Create a fallback sip module with wrapinstance for PySide6
        class ShibokenFallback:
            @staticmethod
            def wrapinstance(address, qclass):
                """Convert a C++ pointer (as integer) to a PySide6 object"""
                try:
                    import shiboken6
                    return shiboken6.wrapInstance(address, qclass)
                except:
                    # Last resort: try ctypes approach
                    return None

        sip = ShibokenFallback()
elif USING_PYSIDE2:
    try:
        import shiboken2 as sip
    except ImportError:
        pass