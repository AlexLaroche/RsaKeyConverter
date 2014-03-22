using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Linq.Expressions;
using System.Text;

namespace RsaKeyConverter.ViewModel
{
    public abstract class Observable : INotifyPropertyChanged, IDisposable
    {
        #region [Private members]

        private bool disposed = false;

        #endregion

        #region [Public members]

        #endregion

        #region [.ctor]

        public Observable()
        {
        }

        #endregion

        #region [INotifyPropertyChanged Members]

        public event PropertyChangedEventHandler PropertyChanged = delegate { };

        protected virtual void RaisePropertyChanged<T>(Expression<Func<T>> expression)
        {
            var property = expression.Body as MemberExpression;

            if (property != null)
            {
                var name = property.Member.Name;

                if (!EventArgs.ContainsKey(name))
                    EventArgs.Add(name, new PropertyChangedEventArgs(name));

                PropertyChanged(this, EventArgs[name]);

                // trigger property changed on other affected properties
                var propertyInfo = GetType().GetProperty(name);
                var affectsProps = propertyInfo.GetCustomAttributes(typeof(AffectsOtherPropertyAttribute), true);

                foreach (AffectsOtherPropertyAttribute otherPropertyAttr in affectsProps)
                    if (!EventArgs.ContainsKey(otherPropertyAttr.AffectsProperty))
                    {
                        EventArgs.Add(name, new PropertyChangedEventArgs(otherPropertyAttr.AffectsProperty));
                        PropertyChanged(this, EventArgs[otherPropertyAttr.AffectsProperty]);
                    }
            }
        }

        protected virtual void RaisePropertyChanged<T>(Expression<Func<T>> expression, ref T field, T value)
        {
            RaisePropertyChanged(expression, ref field, value, null);
        }

        protected virtual void RaisePropertyChanged<T>(Expression<Func<T>> expression, ref T field, T value, Action action)
        {
            var property = expression.Body as MemberExpression;

            if (property != null && !AreEqual(field, value))
            {
                var name = property.Member.Name;

                if (!EventArgs.ContainsKey(name))
                    EventArgs.Add(name, new PropertyChangedEventArgs(name));

                field = value;

                PropertyChanged(this, EventArgs[name]);

                // trigger property changed on other affected properties
                var propertyInfo = GetType().GetProperty(name);
                var affectsProps = propertyInfo.GetCustomAttributes(typeof(AffectsOtherPropertyAttribute), true);

                foreach (AffectsOtherPropertyAttribute otherPropertyAttr in affectsProps)
                    if (!EventArgs.ContainsKey(otherPropertyAttr.AffectsProperty))
                    {
                        EventArgs.Add(name, new PropertyChangedEventArgs(otherPropertyAttr.AffectsProperty));
                        PropertyChanged(this, EventArgs[otherPropertyAttr.AffectsProperty]);
                    }

                if (action != null)
                    action();
            }
        }

        static readonly Dictionary<string, PropertyChangedEventArgs> EventArgs = new Dictionary<string, PropertyChangedEventArgs>();

        static bool AreEqual<T>(T a, T b)
        {
            if (a == null && b == null) return true;

            if (a == null || b == null) return false;

            return a.Equals(b);
        }

        #endregion

        #region [IDisposable Members]

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!disposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {

                }

                // Note disposing has been done.
                disposed = true;
            }
        }

        #endregion
    }

    [AttributeUsage(AttributeTargets.Property, AllowMultiple = true)]
    public sealed class AffectsOtherPropertyAttribute : Attribute
    {
        public AffectsOtherPropertyAttribute(string otherPropertyName)
        {
            AffectsProperty = otherPropertyName;
        }

        public string AffectsProperty
        {
            get;
            private set;
        }
    }
}
